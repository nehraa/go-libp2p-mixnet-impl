package hub

import (
	"context"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/ping"
)

// Receptor is a managed binding between the hub and a single peer.
type Receptor struct {
	hub    *Hub
	id     ReceptorID
	target peer.AddrInfo

	ctx    context.Context
	cancel context.CancelFunc

	mu                    sync.RWMutex
	activeStream          network.Stream
	activeDirection       network.Direction
	lastRTT               time.Duration
	latencyEWMA           time.Duration
	bytesSent             uint64
	bytesReceived         uint64
	connectAttemptCount   uint64
	connectFailureCount   uint64
	streamOpenCount       uint64
	streamCloseCount      uint64
	reconnectCount        uint64
	sendOperationCount    uint64
	receiveOperationCount uint64
	pingSuccessCount      uint64
	pingFailureCount      uint64
	readErrorCount        uint64
	writeErrorCount       uint64
	eventDropCount        uint64
	metricsDropCount      uint64
	backpressureResets    uint64
	streamOpenedAt        time.Time
	firstPacketAt         time.Time
	lastActivityAt        time.Time
	lastSendAt            time.Time
	lastReceiveAt         time.Time
	lastPingSuccessAt     time.Time
	lastPingFailureAt     time.Time
	lastErrorAt           time.Time
	lastError             string
}

func newReceptor(h *Hub, id ReceptorID, target peer.AddrInfo) *Receptor {
	ctx, cancel := context.WithCancel(h.ctx)
	return &Receptor{
		hub:    h,
		id:     id,
		target: copyAddrInfo(target),
		ctx:    ctx,
		cancel: cancel,
	}
}

func copyAddrInfo(info peer.AddrInfo) peer.AddrInfo {
	clone := peer.AddrInfo{ID: info.ID}
	if len(info.Addrs) > 0 {
		clone.Addrs = append(clone.Addrs, info.Addrs...)
	}
	return clone
}

// ID returns the receptor identifier.
func (r *Receptor) ID() ReceptorID {
	return r.id
}

// Peer returns the bound peer identifier.
func (r *Receptor) Peer() peer.ID {
	return r.target.ID
}

// Snapshot returns the receptor state.
func (r *Receptor) Snapshot() Snapshot {
	r.mu.RLock()
	snapshot := r.snapshotLocked()
	activeStream := r.activeStream
	r.mu.RUnlock()
	return r.enrichSnapshot(snapshot, activeStream)
}

// Send writes bytes to the receptor's active stream.
func (r *Receptor) Send(ctx context.Context, payload []byte) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	r.mu.RLock()
	stream := r.activeStream
	r.mu.RUnlock()
	if stream == nil {
		return 0, ErrNoActiveStream
	}

	if deadline, ok := ctx.Deadline(); ok {
		if err := stream.SetWriteDeadline(deadline); err != nil {
			return 0, err
		}
		defer stream.SetWriteDeadline(time.Time{})
	}

	n, err := stream.Write(payload)
	if err != nil {
		log.Warn("receptor send failed", "receptor_id", r.id, "peer", r.target.ID, "err", err)
		r.handleStreamWriteError(stream, err)
		return n, err
	}
	if ctx.Err() != nil {
		return n, ctx.Err()
	}

	r.recordSend(n)
	return n, nil
}

func (r *Receptor) runPingLoop() {
	if r.hub.cfg.PingInterval <= 0 {
		return
	}

	ticker := time.NewTicker(r.hub.cfg.PingInterval)
	defer ticker.Stop()

	r.samplePing()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.samplePing()
		}
	}
}

func (r *Receptor) samplePing() {
	if r.hub.host.Network().Connectedness(r.target.ID) != network.Connected {
		return
	}

	ctx, cancel := context.WithTimeout(r.ctx, r.hub.cfg.PingTimeout)
	defer cancel()

	results := ping.Ping(ctx, r.hub.host, r.target.ID)
	result, ok := <-results
	if !ok || result.Error != nil {
		failureErr := result.Error
		if failureErr == nil {
			failureErr = ctx.Err()
		}
		if failureErr != nil && failureErr != context.Canceled {
			log.Warn("receptor ping failed", "receptor_id", r.id, "peer", r.target.ID, "err", failureErr)
			r.recordPingFailure(failureErr)
			r.hub.publishMetric(MetricKindPingFailed, r, "", failureErr)
		}
		return
	}

	snapshot := r.recordRTT(result.RTT)
	r.hub.emitEvent(Event{
		Kind:       EventKindMetricsUpdated,
		ReceptorID: r.id,
		PeerID:     r.target.ID,
		Snapshot:   snapshot,
	})
	r.hub.publishMetric(MetricKindPingSucceeded, r, "", nil)
}

func (r *Receptor) recordRTT(rtt time.Duration) Snapshot {
	r.mu.Lock()
	now := time.Now()
	r.lastRTT = rtt
	r.latencyEWMA = r.hub.host.Peerstore().LatencyEWMA(r.target.ID)
	r.pingSuccessCount++
	r.lastPingSuccessAt = now
	snapshot := r.snapshotLocked()
	activeStream := r.activeStream
	r.mu.Unlock()
	return r.enrichSnapshot(snapshot, activeStream)
}

func (r *Receptor) recordPingFailure(err error) Snapshot {
	return r.recordError(err, func() {
		r.pingFailureCount++
		r.lastPingFailureAt = time.Now()
	})
}

func (r *Receptor) recordConnectAttempt() {
	r.mu.Lock()
	r.connectAttemptCount++
	r.mu.Unlock()
}

func (r *Receptor) recordConnectFailure(err error) Snapshot {
	return r.recordError(err, func() {
		r.connectFailureCount++
	})
}

func (r *Receptor) recordStreamOpenFailure(err error) Snapshot {
	return r.recordError(err, nil)
}

func (r *Receptor) recordReadError(err error) Snapshot {
	return r.recordError(err, func() {
		r.readErrorCount++
	})
}

func (r *Receptor) recordWriteError(err error) Snapshot {
	return r.recordError(err, func() {
		r.writeErrorCount++
	})
}

func (r *Receptor) recordEventDrop() Snapshot {
	r.mu.Lock()
	r.eventDropCount++
	snapshot := r.snapshotLocked()
	activeStream := r.activeStream
	r.mu.Unlock()
	return r.enrichSnapshot(snapshot, activeStream)
}

func (r *Receptor) recordMetricDrop() Snapshot {
	r.mu.Lock()
	r.metricsDropCount++
	snapshot := r.snapshotLocked()
	activeStream := r.activeStream
	r.mu.Unlock()
	return r.enrichSnapshot(snapshot, activeStream)
}

func (r *Receptor) recordError(err error, mutate func()) Snapshot {
	r.mu.Lock()
	if mutate != nil {
		mutate()
	}
	now := time.Now()
	r.lastErrorAt = now
	r.lastError = err.Error()
	snapshot := r.snapshotLocked()
	activeStream := r.activeStream
	r.mu.Unlock()
	return r.enrichSnapshot(snapshot, activeStream)
}

func (r *Receptor) attachInbound(stream network.Stream) (streamReplacement, error) {
	return r.attachStream(stream, network.DirInbound)
}

func (r *Receptor) attachOutbound(stream network.Stream) (streamReplacement, error) {
	return r.attachStream(stream, network.DirOutbound)
}

func (r *Receptor) attachStream(stream network.Stream, direction network.Direction) (streamReplacement, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.activeStream != nil {
		preferredDirection := r.preferredDirection()
		if r.activeDirection == direction || preferredDirection != direction {
			return streamReplacement{}, ErrActiveStreamExists
		}

		replacement := streamReplacement{
			Replaced: true,
			StreamID: r.activeStream.ID(),
			Stream:   r.activeStream,
		}
		r.setActiveStreamLocked(stream, direction, false)
		return replacement, nil
	}

	r.setActiveStreamLocked(stream, direction, r.streamOpenCount > 0)
	return streamReplacement{}, nil
}

func (r *Receptor) setActiveStreamLocked(stream network.Stream, direction network.Direction, reconnect bool) {
	now := time.Now()
	r.activeStream = stream
	r.activeDirection = direction
	r.streamOpenedAt = now
	r.firstPacketAt = time.Time{}
	r.lastActivityAt = now
	r.streamOpenCount++
	if reconnect {
		r.reconnectCount++
	}
}

func (r *Receptor) preferredDirection() network.Direction {
	if string(r.hub.host.ID()) < string(r.target.ID) {
		return network.DirOutbound
	}
	return network.DirInbound
}

func (r *Receptor) activeStreamPreferred() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.activeStream != nil && r.activeDirection == r.preferredDirection()
}

func (r *Receptor) hasActiveStream() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.activeStream != nil
}

func (r *Receptor) snapshotLocked() Snapshot {
	return Snapshot{
		ReceptorID:            r.id,
		PeerID:                r.target.ID,
		ProtocolID:            r.hub.cfg.ProtocolID,
		PeerAddrs:             slices.Clone(r.target.Addrs),
		HasActiveStream:       r.activeStream != nil,
		ActiveStreamDirection: r.activeDirection,
		LastRTT:               r.lastRTT,
		LatencyEWMA:           r.latencyEWMA,
		BytesSent:             r.bytesSent,
		BytesReceived:         r.bytesReceived,
		ConnectAttemptCount:   r.connectAttemptCount,
		ConnectFailureCount:   r.connectFailureCount,
		StreamOpenCount:       r.streamOpenCount,
		StreamCloseCount:      r.streamCloseCount,
		ReconnectCount:        r.reconnectCount,
		SendOperationCount:    r.sendOperationCount,
		ReceiveOperationCount: r.receiveOperationCount,
		PingSuccessCount:      r.pingSuccessCount,
		PingFailureCount:      r.pingFailureCount,
		ReadErrorCount:        r.readErrorCount,
		WriteErrorCount:       r.writeErrorCount,
		EventDropCount:        r.eventDropCount,
		MetricsDropCount:      r.metricsDropCount,
		BackpressureResets:    r.backpressureResets,
		StreamOpenedAt:        r.streamOpenedAt,
		FirstPacketAt:         r.firstPacketAt,
		LastActivityAt:        r.lastActivityAt,
		LastSendAt:            r.lastSendAt,
		LastReceiveAt:         r.lastReceiveAt,
		LastPingSuccessAt:     r.lastPingSuccessAt,
		LastPingFailureAt:     r.lastPingFailureAt,
		LastErrorAt:           r.lastErrorAt,
		LastError:             r.lastError,
	}
}

func (r *Receptor) enrichSnapshot(snapshot Snapshot, activeStream network.Stream) Snapshot {
	snapshot.Connectedness = r.hub.host.Network().Connectedness(r.target.ID)

	conns := r.hub.host.Network().ConnsToPeer(r.target.ID)
	snapshot.ConnectionCount = len(conns)
	conn := selectSnapshotConn(activeStream, conns)
	if conn == nil {
		return snapshot
	}

	stat := conn.Stat()
	state := conn.ConnState()
	snapshot.ConnectionID = conn.ID()
	snapshot.ConnectionStreamCount = len(conn.GetStreams())
	snapshot.ConnectionDirection = stat.Direction
	snapshot.ConnectionOpenedAt = stat.Opened
	snapshot.ConnectionLimited = stat.Limited
	snapshot.Transport = state.Transport
	snapshot.SecurityProtocol = state.Security
	snapshot.StreamMultiplexer = state.StreamMultiplexer
	snapshot.LocalMultiaddr = conn.LocalMultiaddr()
	snapshot.RemoteMultiaddr = conn.RemoteMultiaddr()
	snapshot.TransportDetails = buildTransportDetails(conn)
	if activeStream != nil {
		snapshot.ActiveStreamID = activeStream.ID()
	}
	return snapshot
}

func selectSnapshotConn(activeStream network.Stream, conns []network.Conn) network.Conn {
	if activeStream != nil {
		return activeStream.Conn()
	}
	if len(conns) == 0 {
		return nil
	}

	selected := conns[0]
	for _, conn := range conns[1:] {
		if conn.Stat().Opened.After(selected.Stat().Opened) {
			selected = conn
		}
	}
	return selected
}

func (r *Receptor) runReadLoop(stream network.Stream) {
	buffer := make([]byte, r.hub.cfg.ReadBufferSize)
	for {
		n, err := stream.Read(buffer)
		if n > 0 {
			chunk := append([]byte(nil), buffer[:n]...)
			snapshot, firstPacket, readErr := r.recordInbound(stream, n)
			if readErr == nil {
				r.hub.emitEvent(Event{
					Kind:          EventKindDataReceived,
					ReceptorID:    r.id,
					PeerID:        r.target.ID,
					StreamID:      stream.ID(),
					Data:          chunk,
					Snapshot:      snapshot,
					IsFirstPacket: firstPacket,
				})
				if firstPacket {
					r.hub.publishMetric(MetricKindFirstPacket, r, stream.ID(), nil)
				}
			}
		}

		if err == nil {
			continue
		}

		streamID, snapshot, detached := r.detachIfCurrent(stream)
		if detached {
			log.Debug("receptor stream closed", "receptor_id", r.id, "peer", r.target.ID, "stream_id", streamID, "err", err)
			r.hub.emitEvent(Event{
				Kind:       EventKindStreamClosed,
				ReceptorID: r.id,
				PeerID:     r.target.ID,
				StreamID:   streamID,
				Snapshot:   snapshot,
			})
			r.hub.publishMetric(MetricKindStreamClosed, r, streamID, nil)
			if err != io.EOF && err != context.Canceled {
				errorSnapshot := r.recordReadError(fmt.Errorf("read receptor stream: %w", err))
				r.hub.emitEvent(Event{
					Kind:       EventKindError,
					ReceptorID: r.id,
					PeerID:     r.target.ID,
					StreamID:   streamID,
					Snapshot:   errorSnapshot,
					Err:        fmt.Errorf("read receptor stream: %w", err),
				})
				r.hub.publishMetric(MetricKindReadFailed, r, streamID, err)
			}
		}
		return
	}
}

func (r *Receptor) recordInbound(stream network.Stream, n int) (Snapshot, bool, error) {
	r.mu.Lock()
	if r.activeStream == nil || r.activeStream.ID() != stream.ID() {
		r.mu.Unlock()
		return Snapshot{}, false, ErrNoActiveStream
	}

	now := time.Now()
	firstPacket := r.firstPacketAt.IsZero()
	if firstPacket {
		r.firstPacketAt = now
	}
	r.bytesReceived += uint64(n)
	r.receiveOperationCount++
	r.lastActivityAt = now
	r.lastReceiveAt = now

	snapshot := r.snapshotLocked()
	activeStream := r.activeStream
	r.mu.Unlock()
	return r.enrichSnapshot(snapshot, activeStream), firstPacket, nil
}

func (r *Receptor) recordSend(n int) {
	r.mu.Lock()
	now := time.Now()
	r.bytesSent += uint64(n)
	r.sendOperationCount++
	r.lastActivityAt = now
	r.lastSendAt = now
	r.mu.Unlock()
}

func (r *Receptor) detachIfCurrent(stream network.Stream) (string, Snapshot, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.activeStream == nil || r.activeStream.ID() != stream.ID() {
		return "", Snapshot{}, false
	}

	streamID := r.activeStream.ID()
	r.activeStream = nil
	r.activeDirection = network.DirUnknown
	r.streamOpenedAt = time.Time{}
	r.streamCloseCount++
	snapshot := r.snapshotLocked()
	return streamID, r.enrichSnapshot(snapshot, nil), true
}

func (r *Receptor) resetActiveStream() (string, Snapshot, bool, error) {
	r.mu.Lock()
	if r.activeStream == nil {
		r.mu.Unlock()
		return "", Snapshot{}, false, nil
	}

	stream := r.activeStream
	streamID := stream.ID()
	r.activeStream = nil
	r.activeDirection = network.DirUnknown
	r.streamOpenedAt = time.Time{}
	r.streamCloseCount++
	snapshot := r.snapshotLocked()
	r.mu.Unlock()

	return streamID, r.enrichSnapshot(snapshot, nil), true, stream.Reset()
}

func (r *Receptor) handlePeerOffline() (string, Snapshot, bool, error) {
	return r.resetActiveStream()
}

func (r *Receptor) handleStreamWriteError(stream network.Stream, cause error) {
	streamID, snapshot, detached := r.detachIfCurrent(stream)
	if !detached {
		return
	}

	errorSnapshot := r.recordWriteError(fmt.Errorf("write receptor stream: %w", cause))
	r.hub.emitEvent(Event{
		Kind:       EventKindStreamClosed,
		ReceptorID: r.id,
		PeerID:     r.target.ID,
		StreamID:   streamID,
		Snapshot:   snapshot,
	})
	r.hub.emitEvent(Event{
		Kind:       EventKindError,
		ReceptorID: r.id,
		PeerID:     r.target.ID,
		StreamID:   streamID,
		Snapshot:   errorSnapshot,
		Err:        fmt.Errorf("write receptor stream: %w", cause),
	})
	r.hub.publishMetric(MetricKindStreamClosed, r, streamID, nil)
	r.hub.publishMetric(MetricKindWriteFailed, r, streamID, cause)
}

func (r *Receptor) handleEventOverflow(evt Event) (Snapshot, string, bool, error) {
	snapshot := r.recordEventDrop()
	if evt.Kind != EventKindDataReceived || evt.StreamID == "" {
		return snapshot, "", false, nil
	}

	r.mu.Lock()
	if r.activeStream == nil || r.activeStream.ID() != evt.StreamID {
		snapshot = r.snapshotLocked()
		activeStream := r.activeStream
		r.mu.Unlock()
		return r.enrichSnapshot(snapshot, activeStream), "", false, nil
	}

	stream := r.activeStream
	streamID := stream.ID()
	r.activeStream = nil
	r.activeDirection = network.DirUnknown
	r.streamOpenedAt = time.Time{}
	r.streamCloseCount++
	r.backpressureResets++
	r.lastErrorAt = time.Now()
	r.lastError = ErrEventBufferFull.Error()
	snapshot = r.snapshotLocked()
	r.mu.Unlock()

	return r.enrichSnapshot(snapshot, nil), streamID, true, stream.Reset()
}

func (r *Receptor) close() error {
	_, _, _, err := r.shutdown()
	return err
}

func (r *Receptor) shutdown() (string, Snapshot, bool, error) {
	r.cancel()
	return r.resetActiveStream()
}

type streamReplacement struct {
	Replaced bool
	StreamID string
	Stream   network.Stream
}
