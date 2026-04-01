package hub

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/host/eventbus"

	logging "github.com/libp2p/go-libp2p/gologshim"
)

var log = logging.Logger("hub")

type hubLifecycleState uint32

const (
	hubStateOpen hubLifecycleState = iota
	hubStateClosing
	hubStateClosed
)

// Hub manages receptors for a single host.
type Hub struct {
	host host.Host
	cfg  Config

	ctx    context.Context
	cancel context.CancelFunc

	notifiee         *network.NotifyBundle
	connectednessSub event.Subscription

	events  chan Event
	metrics chan MetricUpdate

	closeOnce sync.Once
	wg        sync.WaitGroup
	nextID    atomic.Uint64
	lifecycle atomic.Uint32
	publishMu sync.RWMutex
	closed    bool

	mu              sync.RWMutex
	receptorsByID   map[ReceptorID]*Receptor
	receptorsByPeer map[peer.ID]*Receptor
}

// New creates a hub that manages receptors on top of a host.
func New(h host.Host, cfg Config) (*Hub, error) {
	if h == nil {
		return nil, fmt.Errorf("%w: host is required", ErrInvalidConfig)
	}
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	if slices.Contains(h.Mux().Protocols(), normalized.ProtocolID) {
		return nil, fmt.Errorf("%w: protocol %s", ErrProtocolHandlerConflict, normalized.ProtocolID)
	}

	ctx, cancel := context.WithCancel(context.Background())
	hub := &Hub{
		host:            h,
		cfg:             normalized,
		ctx:             ctx,
		cancel:          cancel,
		events:          make(chan Event, normalized.EventBufferSize),
		metrics:         make(chan MetricUpdate, normalized.MetricsBufferSize),
		receptorsByID:   make(map[ReceptorID]*Receptor),
		receptorsByPeer: make(map[peer.ID]*Receptor),
	}
	hub.lifecycle.Store(uint32(hubStateOpen))

	hub.notifiee = &network.NotifyBundle{
		ConnectedF:    hub.handleConnected,
		DisconnectedF: hub.handleDisconnected,
	}
	h.Network().Notify(hub.notifiee)

	sub, err := h.EventBus().Subscribe(
		new(event.EvtPeerConnectednessChanged),
		eventbus.Name("hub"),
		eventbus.BufSize(normalized.EventBufferSize),
	)
	if err != nil {
		h.Network().StopNotify(hub.notifiee)
		cancel()
		return nil, fmt.Errorf("subscribe to connectedness events: %w", err)
	}
	hub.connectednessSub = sub
	h.SetStreamHandler(normalized.ProtocolID, hub.handleStream)

	hub.wg.Add(1)
	go func() {
		defer hub.wg.Done()
		hub.runConnectednessLoop()
	}()

	log.Debug("hub started", "peer", h.ID(), "protocol", normalized.ProtocolID)
	return hub, nil
}

// Events returns the bounded event stream for lifecycle and data delivery.
func (h *Hub) Events() <-chan Event {
	return h.events
}

// Metrics returns the dedicated bounded metrics and observability stream.
func (h *Hub) Metrics() <-chan MetricUpdate {
	return h.metrics
}

// CreateReceptor registers a receptor for a peer and attempts to open its stream.
// A non-nil receptor may be returned together with an error when the binding is
// created successfully but the initial stream cannot be opened.
func (h *Hub) CreateReceptor(ctx context.Context, target peer.AddrInfo) (*Receptor, error) {
	if err := h.ensureOpen(); err != nil {
		return nil, err
	}
	if target.ID == "" {
		return nil, fmt.Errorf("%w: target peer id is required", ErrInvalidConfig)
	}
	if target.ID == h.host.ID() {
		return nil, fmt.Errorf("%w: peer %s", ErrSelfBinding, target.ID)
	}
	if ctx == nil {
		ctx = context.Background()
	}

	h.mu.Lock()
	if h.lifecycleState() != hubStateOpen {
		h.mu.Unlock()
		return nil, ErrHubClosed
	}
	if _, exists := h.receptorsByPeer[target.ID]; exists {
		h.mu.Unlock()
		return nil, fmt.Errorf("%w: peer %s", ErrDuplicatePeerBinding, target.ID)
	}

	receptorID := ReceptorID(fmt.Sprintf("receptor-%d", h.nextID.Add(1)))
	receptor := newReceptor(h, receptorID, target)
	h.receptorsByID[receptorID] = receptor
	h.receptorsByPeer[target.ID] = receptor
	h.mu.Unlock()

	if err := h.ensureOpen(); err != nil {
		h.rollbackReceptor(receptor)
		return nil, err
	}

	snapshot := receptor.Snapshot()
	h.emitEvent(Event{
		Kind:       EventKindReceptorCreated,
		ReceptorID: receptor.id,
		PeerID:     receptor.target.ID,
		Snapshot:   snapshot,
	})
	h.publishMetric(MetricKindReceptorCreated, receptor, "", nil)

	log.Debug("receptor created", "receptor_id", receptor.id, "peer", receptor.target.ID)

	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		receptor.runPingLoop()
	}()

	if err := h.OpenStream(ctx, receptor.id); err != nil {
		if errors.Is(err, ErrHubClosed) {
			h.rollbackReceptor(receptor)
			return nil, err
		}
		h.emitEvent(Event{
			Kind:       EventKindError,
			ReceptorID: receptor.id,
			PeerID:     receptor.target.ID,
			Snapshot:   receptor.Snapshot(),
			Err:        err,
		})
		return receptor, err
	}
	return receptor, nil
}

// OpenStream ensures the receptor has an outbound stream when needed.
func (h *Hub) OpenStream(ctx context.Context, id ReceptorID) error {
	if err := h.ensureOpen(); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	opCtx, cancel := h.operationContext(ctx)
	defer cancel()

	receptor, err := h.receptorByID(id)
	if err != nil {
		if closeErr := h.ensureOpen(); closeErr != nil {
			return closeErr
		}
		return err
	}
	if receptor.activeStreamPreferred() || receptor.hasActiveStream() {
		return nil
	}

	receptor.recordConnectAttempt()
	if len(receptor.target.Addrs) > 0 {
		h.host.Peerstore().AddAddrs(receptor.target.ID, receptor.target.Addrs, peerstore.TempAddrTTL)
	}

	if err := h.ensureOpen(); err != nil {
		return err
	}
	if err := h.host.Connect(opCtx, receptor.target); err != nil {
		if closeErr := h.ensureOpen(); closeErr != nil {
			return closeErr
		}
		snapshot := receptor.recordConnectFailure(err)
		openErr := fmt.Errorf("connect receptor %s to peer %s: %w", receptor.id, receptor.target.ID, err)
		log.Warn("receptor connect failed", "receptor_id", receptor.id, "peer", receptor.target.ID, "err", err)
		h.emitEvent(Event{
			Kind:       EventKindError,
			ReceptorID: receptor.id,
			PeerID:     receptor.target.ID,
			Snapshot:   snapshot,
			Err:        openErr,
		})
		h.publishMetric(MetricKindConnectFailed, receptor, "", openErr)
		return openErr
	}

	if err := h.ensureOpen(); err != nil {
		return err
	}
	stream, err := h.host.NewStream(opCtx, receptor.target.ID, h.cfg.ProtocolID)
	if err != nil {
		if closeErr := h.ensureOpen(); closeErr != nil {
			return closeErr
		}
		snapshot := receptor.recordStreamOpenFailure(err)
		openErr := fmt.Errorf("open receptor stream %s to peer %s: %w", receptor.id, receptor.target.ID, err)
		log.Warn("receptor open stream failed", "receptor_id", receptor.id, "peer", receptor.target.ID, "err", err)
		h.emitEvent(Event{
			Kind:       EventKindError,
			ReceptorID: receptor.id,
			PeerID:     receptor.target.ID,
			Snapshot:   snapshot,
			Err:        openErr,
		})
		h.publishMetric(MetricKindStreamOpenFailed, receptor, "", openErr)
		return openErr
	}
	if err := h.ensureOpen(); err != nil {
		_ = stream.Reset()
		return err
	}

	replacement, err := receptor.attachOutbound(stream)
	if err != nil {
		_ = stream.Reset()
		if err == ErrActiveStreamExists {
			return nil
		}
		return err
	}
	if err := h.ensureOpen(); err != nil {
		h.rollbackAttachedStream(receptor, replacement)
		return err
	}

	h.finishStreamAttach(receptor, stream, replacement)
	return nil
}

// ResetStream terminates a receptor's active stream without removing the receptor.
func (h *Hub) ResetStream(id ReceptorID) error {
	if err := h.ensureOpen(); err != nil {
		return err
	}
	receptor, err := h.receptorByID(id)
	if err != nil {
		if closeErr := h.ensureOpen(); closeErr != nil {
			return closeErr
		}
		return err
	}

	streamID, snapshot, hadStream, resetErr := receptor.resetActiveStream()
	if !hadStream {
		return ErrNoActiveStream
	}
	if resetErr != nil {
		log.Warn("receptor reset failed", "receptor_id", id, "peer", receptor.target.ID, "err", resetErr)
	}

	h.emitEvent(Event{
		Kind:       EventKindStreamClosed,
		ReceptorID: receptor.id,
		PeerID:     receptor.target.ID,
		StreamID:   streamID,
		Snapshot:   snapshot,
	})
	h.publishMetric(MetricKindStreamClosed, receptor, streamID, resetErr)
	return resetErr
}

// RemoveReceptor removes a receptor and terminates its active stream.
func (h *Hub) RemoveReceptor(id ReceptorID) error {
	if err := h.ensureOpen(); err != nil {
		return err
	}
	receptor, err := h.removeReceptor(id)
	if err != nil {
		if closeErr := h.ensureOpen(); closeErr != nil {
			return closeErr
		}
		return err
	}

	if err := receptor.close(); err != nil {
		log.Warn("receptor close failed", "receptor_id", id, "peer", receptor.target.ID, "err", err)
	}

	snapshot := receptor.Snapshot()
	h.emitEvent(Event{
		Kind:       EventKindReceptorRemoved,
		ReceptorID: receptor.id,
		PeerID:     receptor.target.ID,
		Snapshot:   snapshot,
	})
	h.publishMetric(MetricKindReceptorRemoved, receptor, "", nil)

	log.Debug("receptor removed", "receptor_id", receptor.id, "peer", receptor.target.ID)
	return nil
}

// Snapshot returns a receptor snapshot.
func (h *Hub) Snapshot(id ReceptorID) (Snapshot, error) {
	if err := h.ensureOpen(); err != nil {
		return Snapshot{}, err
	}
	receptor, err := h.receptorByID(id)
	if err != nil {
		if closeErr := h.ensureOpen(); closeErr != nil {
			return Snapshot{}, closeErr
		}
		return Snapshot{}, err
	}
	return receptor.Snapshot(), nil
}

// Snapshots returns all receptor snapshots.
func (h *Hub) Snapshots() []Snapshot {
	if h.lifecycleState() != hubStateOpen {
		return nil
	}
	h.mu.RLock()
	receptors := make([]*Receptor, 0, len(h.receptorsByID))
	for _, receptor := range h.receptorsByID {
		receptors = append(receptors, receptor)
	}
	h.mu.RUnlock()

	snapshots := make([]Snapshot, 0, len(receptors))
	for _, receptor := range receptors {
		snapshots = append(snapshots, receptor.Snapshot())
	}
	return snapshots
}

// Close shuts the hub down and removes all receptors.
func (h *Hub) Close() error {
	h.closeOnce.Do(func() {
		h.lifecycle.Store(uint32(hubStateClosing))
		h.cancel()
		h.host.RemoveStreamHandler(h.cfg.ProtocolID)
		h.host.Network().StopNotify(h.notifiee)
		if h.connectednessSub != nil {
			_ = h.connectednessSub.Close()
		}

		h.mu.Lock()
		receptors := make([]*Receptor, 0, len(h.receptorsByID))
		for _, receptor := range h.receptorsByID {
			receptors = append(receptors, receptor)
		}
		h.receptorsByID = make(map[ReceptorID]*Receptor)
		h.receptorsByPeer = make(map[peer.ID]*Receptor)
		h.mu.Unlock()

		for _, receptor := range receptors {
			streamID, snapshot, hadStream, closeErr := receptor.shutdown()
			if hadStream {
				if closeErr != nil {
					log.Warn("receptor shutdown reset failed", "receptor_id", receptor.id, "peer", receptor.target.ID, "err", closeErr)
				}
				h.emitEvent(Event{
					Kind:       EventKindStreamClosed,
					ReceptorID: receptor.id,
					PeerID:     receptor.target.ID,
					StreamID:   streamID,
					Snapshot:   snapshot,
				})
				h.publishMetric(MetricKindStreamClosed, receptor, streamID, closeErr)
			}

			finalSnapshot := receptor.Snapshot()
			h.emitEvent(Event{
				Kind:       EventKindReceptorRemoved,
				ReceptorID: receptor.id,
				PeerID:     receptor.target.ID,
				Snapshot:   finalSnapshot,
			})
			h.publishMetric(MetricKindReceptorRemoved, receptor, "", nil)
		}

		h.cancel()
		h.wg.Wait()
		h.publishMu.Lock()
		h.closed = true
		close(h.events)
		close(h.metrics)
		h.publishMu.Unlock()
		h.lifecycle.Store(uint32(hubStateClosed))
		log.Debug("hub stopped", "peer", h.host.ID(), "protocol", h.cfg.ProtocolID)
	})
	return nil
}

func (h *Hub) runConnectednessLoop() {
	for {
		select {
		case <-h.ctx.Done():
			return
		case evt, ok := <-h.connectednessSub.Out():
			if !ok {
				return
			}

			connectedness, ok := evt.(event.EvtPeerConnectednessChanged)
			if !ok || connectedness.Connectedness != network.NotConnected {
				continue
			}

			receptor := h.receptorByPeerID(connectedness.Peer)
			if receptor == nil {
				continue
			}

			streamID, snapshot, hadStream, resetErr := receptor.handlePeerOffline()
			if hadStream {
				if resetErr != nil {
					log.Warn("receptor peer-offline reset failed", "receptor_id", receptor.id, "peer", receptor.target.ID, "err", resetErr)
				}
				h.emitEvent(Event{
					Kind:       EventKindStreamClosed,
					ReceptorID: receptor.id,
					PeerID:     receptor.target.ID,
					StreamID:   streamID,
					Snapshot:   snapshot,
				})
				h.publishMetric(MetricKindStreamClosed, receptor, streamID, resetErr)
			} else {
				snapshot = receptor.Snapshot()
			}

			log.Debug("receptor peer offline", "receptor_id", receptor.id, "peer", receptor.target.ID)
			h.emitEvent(Event{
				Kind:       EventKindPeerOffline,
				ReceptorID: receptor.id,
				PeerID:     receptor.target.ID,
				Snapshot:   snapshot,
			})
			h.publishMetric(MetricKindPeerOffline, receptor, streamID, nil)
		}
	}
}

func (h *Hub) handleStream(stream network.Stream) {
	if h.lifecycleState() != hubStateOpen {
		_ = stream.Reset()
		return
	}
	receptor := h.receptorByPeerID(stream.Conn().RemotePeer())
	if receptor == nil {
		err := fmt.Errorf("peer %s has no receptor binding", stream.Conn().RemotePeer())
		log.Warn("rejecting inbound hub stream", "peer", stream.Conn().RemotePeer(), "stream_id", stream.ID(), "err", err)
		h.emitEvent(Event{
			Kind:     EventKindError,
			PeerID:   stream.Conn().RemotePeer(),
			StreamID: stream.ID(),
			Err:      err,
		})
		_ = stream.Reset()
		return
	}

	replacement, err := receptor.attachInbound(stream)
	if err != nil {
		if err != ErrActiveStreamExists {
			log.Warn("rejecting inbound hub stream", "receptor_id", receptor.id, "peer", receptor.target.ID, "stream_id", stream.ID(), "err", err)
			h.emitEvent(Event{
				Kind:       EventKindError,
				ReceptorID: receptor.id,
				PeerID:     receptor.target.ID,
				StreamID:   stream.ID(),
				Snapshot:   receptor.Snapshot(),
				Err:        err,
			})
		} else {
			log.Debug("ignoring non-preferred inbound hub stream", "receptor_id", receptor.id, "peer", receptor.target.ID, "stream_id", stream.ID())
		}
		_ = stream.Reset()
		return
	}

	h.finishStreamAttach(receptor, stream, replacement)
}

func (h *Hub) finishStreamAttach(receptor *Receptor, stream network.Stream, replacement streamReplacement) {
	if h.lifecycleState() != hubStateOpen {
		h.rollbackAttachedStream(receptor, replacement)
		return
	}
	if replacement.Replaced {
		if err := replacement.Stream.Reset(); err != nil {
			log.Warn("closing replaced receptor stream failed", "receptor_id", receptor.id, "peer", receptor.target.ID, "stream_id", replacement.StreamID, "err", err)
		}
		h.emitEvent(Event{
			Kind:       EventKindStreamClosed,
			ReceptorID: receptor.id,
			PeerID:     receptor.target.ID,
			StreamID:   replacement.StreamID,
			Snapshot:   receptor.Snapshot(),
		})
		h.publishMetric(MetricKindStreamClosed, receptor, replacement.StreamID, nil)
	}

	snapshot := receptor.Snapshot()
	log.Debug("receptor stream opened", "receptor_id", receptor.id, "peer", receptor.target.ID, "stream_id", stream.ID(), "direction", stream.Stat().Direction)
	h.emitEvent(Event{
		Kind:       EventKindStreamOpened,
		ReceptorID: receptor.id,
		PeerID:     receptor.target.ID,
		StreamID:   stream.ID(),
		Snapshot:   snapshot,
	})
	h.publishMetric(MetricKindStreamOpened, receptor, stream.ID(), nil)

	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		receptor.runReadLoop(stream)
	}()
}

func (h *Hub) emitEvent(evt Event) bool {
	h.publishMu.RLock()
	defer h.publishMu.RUnlock()
	if h.closed {
		return false
	}

	evt.OccurredAt = nowOrExisting(evt.OccurredAt)
	select {
	case h.events <- evt:
		return true
	default:
		h.handleEventOverflow(evt)
		return false
	}
}

func (h *Hub) emitMetric(update MetricUpdate) bool {
	h.publishMu.RLock()
	defer h.publishMu.RUnlock()
	if h.closed {
		return false
	}

	update.OccurredAt = nowOrExisting(update.OccurredAt)
	select {
	case h.metrics <- update:
		return true
	default:
		h.handleMetricOverflow(update)
		return false
	}
}

func (h *Hub) publishMetric(kind MetricKind, receptor *Receptor, streamID string, metricErr error) {
	if receptor == nil {
		return
	}
	h.emitMetric(MetricUpdate{
		Kind:       kind,
		ReceptorID: receptor.id,
		PeerID:     receptor.target.ID,
		StreamID:   streamID,
		Snapshot:   receptor.Snapshot(),
		Err:        metricErr,
	})
}

func (h *Hub) handleEventOverflow(evt Event) {
	receptor := h.receptorByPeerID(evt.PeerID)
	if receptor == nil {
		log.Warn("hub event buffer full", "kind", evt.Kind, "peer", evt.PeerID)
		return
	}

	snapshot, streamID, resetApplied, resetErr := receptor.handleEventOverflow(evt, h.cfg.EventOverflowPolicy)
	log.Warn(
		"hub event buffer full",
		"kind", evt.Kind,
		"receptor_id", receptor.id,
		"peer", receptor.target.ID,
		"stream_id", evt.StreamID,
		"active_stream", snapshot.HasActiveStream,
	)

	h.emitMetric(MetricUpdate{
		Kind:       MetricKindEventDropped,
		ReceptorID: receptor.id,
		PeerID:     receptor.target.ID,
		StreamID:   evt.StreamID,
		Snapshot:   snapshot,
		Err:        ErrEventBufferFull,
	})
	if h.cfg.EventOverflowPolicy != OverflowPolicyResetStream || !resetApplied {
		return
	}

	if resetErr != nil {
		log.Warn("receptor backpressure reset failed", "receptor_id", receptor.id, "peer", receptor.target.ID, "stream_id", streamID, "err", resetErr)
	}
	h.emitMetric(MetricUpdate{
		Kind:       MetricKindBackpressure,
		ReceptorID: receptor.id,
		PeerID:     receptor.target.ID,
		StreamID:   streamID,
		Snapshot:   receptor.Snapshot(),
		Err:        ErrEventBufferFull,
	})
}

func (h *Hub) handleMetricOverflow(update MetricUpdate) {
	receptor := h.receptorByPeerID(update.PeerID)
	if receptor != nil {
		snapshot := receptor.recordMetricDrop()
		log.Warn(
			"hub metrics buffer full",
			"kind", update.Kind,
			"receptor_id", receptor.id,
			"peer", receptor.target.ID,
			"metrics_drop_count", snapshot.MetricsDropCount,
		)
		return
	}
	log.Warn("hub metrics buffer full", "kind", update.Kind, "peer", update.PeerID)
}

func nowOrExisting(value time.Time) time.Time {
	if !value.IsZero() {
		return value
	}
	return time.Now()
}

func (h *Hub) lifecycleState() hubLifecycleState {
	return hubLifecycleState(h.lifecycle.Load())
}

func (h *Hub) ensureOpen() error {
	if h.lifecycleState() != hubStateOpen {
		return ErrHubClosed
	}
	return nil
}

func (h *Hub) operationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	opCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(h.ctx, cancel)
	return opCtx, func() {
		stop()
		cancel()
	}
}

func (h *Hub) rollbackReceptor(receptor *Receptor) {
	if receptor == nil {
		return
	}

	h.mu.Lock()
	if current := h.receptorsByID[receptor.id]; current == receptor {
		delete(h.receptorsByID, receptor.id)
	}
	if current := h.receptorsByPeer[receptor.target.ID]; current == receptor {
		delete(h.receptorsByPeer, receptor.target.ID)
	}
	h.mu.Unlock()

	_ = receptor.close()
}

func (h *Hub) rollbackAttachedStream(receptor *Receptor, replacement streamReplacement) {
	if replacement.Replaced && replacement.Stream != nil {
		_ = replacement.Stream.Reset()
	}
	if receptor != nil {
		_, _, _, _ = receptor.resetActiveStream()
	}
}

func (h *Hub) receptorByID(id ReceptorID) (*Receptor, error) {
	h.mu.RLock()
	receptor := h.receptorsByID[id]
	h.mu.RUnlock()
	if receptor == nil {
		return nil, fmt.Errorf("%w: %s", ErrReceptorNotFound, id)
	}
	return receptor, nil
}

func (h *Hub) receptorByPeerID(peerID peer.ID) *Receptor {
	h.mu.RLock()
	receptor := h.receptorsByPeer[peerID]
	h.mu.RUnlock()
	return receptor
}

func (h *Hub) removeReceptor(id ReceptorID) (*Receptor, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	receptor := h.receptorsByID[id]
	if receptor == nil {
		return nil, fmt.Errorf("%w: %s", ErrReceptorNotFound, id)
	}

	delete(h.receptorsByID, id)
	delete(h.receptorsByPeer, receptor.target.ID)
	return receptor, nil
}

func (h *Hub) handleConnected(_ network.Network, conn network.Conn) {
	receptor := h.receptorByPeerID(conn.RemotePeer())
	if receptor == nil {
		return
	}
	log.Debug("receptor peer connected", "receptor_id", receptor.id, "peer", receptor.target.ID, "remote_multiaddr", conn.RemoteMultiaddr())
}

func (h *Hub) handleDisconnected(_ network.Network, conn network.Conn) {
	receptor := h.receptorByPeerID(conn.RemotePeer())
	if receptor == nil {
		return
	}
	log.Debug("receptor peer disconnected", "receptor_id", receptor.id, "peer", receptor.target.ID, "remote_multiaddr", conn.RemoteMultiaddr())
}
