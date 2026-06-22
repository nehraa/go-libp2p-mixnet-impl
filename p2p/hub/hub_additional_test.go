package hub

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

func TestNewRejectsNilHost(t *testing.T) {
	_, err := New(nil, Config{ProtocolID: testProtocol})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidConfig)
}

func TestCreateReceptorAllowsNilContextAndReturnsReceptorOnInitialStreamFailure(t *testing.T) {
	mn, h1, h2 := newMockHosts(t)
	defer mn.Close()

	hub, err := New(h1, Config{ProtocolID: testProtocol})
	require.NoError(t, err)
	defer hub.Close()

	receptor, err := hub.CreateReceptor(nil, peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()})
	require.NotNil(t, receptor)
	require.Error(t, err)

	empty, emptyErr := hub.CreateReceptor(context.Background(), peer.AddrInfo{})
	require.Nil(t, empty)
	require.ErrorIs(t, emptyErr, ErrInvalidConfig)
}

func TestOpenStreamResetRemoveAndSnapshotRejectMissingReceptor(t *testing.T) {
	mn, h1, _ := newMockHosts(t)
	defer mn.Close()

	hub, err := New(h1, Config{ProtocolID: testProtocol})
	require.NoError(t, err)
	defer hub.Close()

	require.ErrorIs(t, hub.OpenStream(context.Background(), ReceptorID("missing")), ErrReceptorNotFound)
	require.ErrorIs(t, hub.ResetStream(ReceptorID("missing")), ErrReceptorNotFound)
	require.ErrorIs(t, hub.RemoveReceptor(ReceptorID("missing")), ErrReceptorNotFound)
	_, err = hub.Snapshot(ReceptorID("missing"))
	require.ErrorIs(t, err, ErrReceptorNotFound)
}

func TestEmitEventAndMetricRespectClosedHub(t *testing.T) {
	mn, h1, _ := newMockHosts(t)
	defer mn.Close()

	hub, err := New(h1, Config{ProtocolID: testProtocol})
	require.NoError(t, err)
	require.NoError(t, hub.Close())

	require.False(t, hub.emitEvent(Event{}))
	require.False(t, hub.emitMetric(MetricUpdate{}))
	hub.publishMetric(MetricKindEventDropped, nil, "", nil)
}

func TestPublishMetricNoOpsForNilReceptor(t *testing.T) {
	mn, h1, _ := newMockHosts(t)
	defer mn.Close()

	hub, err := New(h1, Config{ProtocolID: testProtocol})
	require.NoError(t, err)
	defer hub.Close()

	require.NotPanics(t, func() {
		hub.publishMetric(MetricKindPeerOffline, nil, "", nil)
	})
}

func TestNowOrExistingUsesProvidedValue(t *testing.T) {
	existing := time.Unix(123, 0)
	require.Equal(t, existing, nowOrExisting(existing))
	require.NotZero(t, nowOrExisting(time.Time{}))
}

func TestRollbackReceptorAndRemoveReceptorMissingBranches(t *testing.T) {
	mn, h1, h2 := newMockHosts(t)
	defer mn.Close()

	hub := newManualHub(t, h1, Config{ProtocolID: testProtocol})
	require.NotPanics(t, func() {
		hub.rollbackReceptor(nil)
	})

	_, err := hub.removeReceptor(ReceptorID("missing"))
	require.ErrorIs(t, err, ErrReceptorNotFound)

	receptor := newReceptor(hub, ReceptorID("rollback"), peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()})
	hub.mu.Lock()
	hub.receptorsByID[receptor.id] = receptor
	hub.receptorsByPeer[receptor.target.ID] = receptor
	hub.mu.Unlock()

	hub.rollbackReceptor(receptor)
	_, err = hub.receptorByID(receptor.id)
	require.ErrorIs(t, err, ErrReceptorNotFound)
}

func TestRollbackAttachedStreamResetsReplacementAndCurrentStream(t *testing.T) {
	mn, h1, h2 := newMockHosts(t)
	defer mn.Close()

	installDiscardHandler(h2, testProtocol)

	hub := newManualHub(t, h1, Config{ProtocolID: testProtocol})
	defer hub.Close()

	receptor := newReceptor(hub, ReceptorID("rollback-stream"), peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()})
	insertReceptor(hub, receptor)

	current := mustOpenStream(t, h1, h2.ID())
	replacement := mustOpenStream(t, h1, h2.ID())
	trackedCurrent := &trackingStream{Stream: current}
	trackedReplacement := &trackingStream{Stream: replacement}

	setReceptorStream(receptor, trackedCurrent, network.DirOutbound)
	hub.rollbackAttachedStream(receptor, streamReplacement{Replaced: true, Stream: trackedReplacement})

	require.True(t, trackedReplacement.resetCalled)
	require.True(t, trackedCurrent.resetCalled)
}

func TestFinishStreamAttachReplacementBranch(t *testing.T) {
	mn, h1, h2 := newMockHosts(t)
	defer mn.Close()

	installDiscardHandler(h2, testProtocol)

	hub := newManualHub(t, h1, Config{ProtocolID: testProtocol})
	defer hub.Close()

	receptor := newReceptor(hub, ReceptorID("replacement"), peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()})
	insertReceptor(hub, receptor)

	preferred := receptor.preferredDirection()
	current := mustOpenStream(t, h1, h2.ID())
	next := mustOpenStream(t, h1, h2.ID())
	trackedCurrent := &trackingStream{Stream: current}
	trackedNext := &trackingStream{Stream: next}

	setReceptorStream(receptor, trackedCurrent, oppositeDirection(preferred))
	replacement, err := receptor.attachStream(trackedNext, preferred)
	require.NoError(t, err)
	require.True(t, replacement.Replaced)

	hub.finishStreamAttach(receptor, trackedNext, replacement)

	require.True(t, trackedCurrent.resetCalled)
	require.NoError(t, hub.Close())
}

func TestFinishStreamAttachClosedHubRollsBack(t *testing.T) {
	mn, h1, h2 := newMockHosts(t)
	defer mn.Close()

	installDiscardHandler(h2, testProtocol)

	hub := newManualHub(t, h1, Config{ProtocolID: testProtocol})
	defer hub.Close()

	receptor := newReceptor(hub, ReceptorID("closed"), peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()})
	insertReceptor(hub, receptor)

	preferred := receptor.preferredDirection()
	current := mustOpenStream(t, h1, h2.ID())
	next := mustOpenStream(t, h1, h2.ID())
	trackedCurrent := &trackingStream{Stream: current}
	trackedNext := &trackingStream{Stream: next}

	setReceptorStream(receptor, trackedCurrent, oppositeDirection(preferred))
	replacement, err := receptor.attachStream(trackedNext, preferred)
	require.NoError(t, err)
	require.True(t, replacement.Replaced)

	markHubClosed(hub)
	hub.finishStreamAttach(receptor, trackedNext, replacement)

	require.True(t, trackedCurrent.resetCalled)
	require.True(t, trackedNext.resetCalled)
}

func TestReceptorSendNoActiveStreamAndDeadlineError(t *testing.T) {
	mn, h1, h2 := newMockHosts(t)
	defer mn.Close()

	hub := newManualHub(t, h1, Config{ProtocolID: testProtocol})
	defer hub.Close()

	receptor := newReceptor(hub, ReceptorID("send"), peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()})

	_, err := receptor.Send(context.Background(), []byte("payload"))
	require.ErrorIs(t, err, ErrNoActiveStream)

	installDiscardHandler(h2, testProtocol)
	stream := mustOpenStream(t, h1, h2.ID())
	tracked := &trackingStream{
		Stream:           stream,
		writeDeadlineErr: errors.New("deadline rejected"),
	}
	setReceptorStream(receptor, tracked, network.DirOutbound)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second))
	defer cancel()

	n, sendErr := receptor.Send(ctx, []byte("payload"))
	require.Zero(t, n)
	require.Error(t, sendErr)
	require.Contains(t, sendErr.Error(), "deadline rejected")
}

func TestRunPingLoopReturnsWhenDisabledOrCancelled(t *testing.T) {
	mn, h1, h2 := newMockHosts(t)
	defer mn.Close()

	disabledHub := newManualHub(t, h1, Config{ProtocolID: testProtocol, PingInterval: 0})
	disabledReceptor := newReceptor(disabledHub, ReceptorID("disabled"), peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()})
	disabledReceptor.runPingLoop()

	cancelledHub := newManualHub(t, h1, Config{ProtocolID: testProtocol, PingInterval: time.Millisecond})
	cancelledReceptor := newReceptor(cancelledHub, ReceptorID("cancelled"), peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()})
	cancelledReceptor.cancel()
	cancelledReceptor.runPingLoop()
}

func TestHandleDisconnectedKnownPeerAndConnectednessLoop(t *testing.T) {
	mn, h1, h2 := newMockHosts(t)
	defer mn.Close()

	installDiscardHandler(h2, testProtocol)

	hub := newManualHub(t, h1, Config{ProtocolID: testProtocol, EventBufferSize: 8, MetricsBufferSize: 8})
	defer hub.Close()

	receptor := newReceptor(hub, ReceptorID("connectedness"), peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()})
	insertReceptor(hub, receptor)

	stream := mustOpenStream(t, h1, h2.ID())
	tracked := &trackingStream{Stream: stream}
	setReceptorStream(receptor, tracked, network.DirOutbound)

	hub.handleDisconnected(h1.Network(), tracked.Conn())

	sub := &fakeSubscription{ch: make(chan any, 8), name: "connectedness"}
	hub.connectednessSub = sub

	done := make(chan struct{})
	go func() {
		hub.runConnectednessLoop()
		close(done)
	}()

	sub.ch <- "ignore"
	sub.ch <- event.EvtPeerConnectednessChanged{Peer: h2.ID(), Connectedness: network.Connected}
	sub.ch <- event.EvtPeerConnectednessChanged{Peer: peer.ID("missing"), Connectedness: network.NotConnected}
	sub.ch <- event.EvtPeerConnectednessChanged{Peer: h2.ID(), Connectedness: network.NotConnected}
	close(sub.ch)

	waitForEvent(t, hub.Events(), 2*time.Second, func(evt Event) bool {
		return evt.Kind == EventKindPeerOffline && evt.ReceptorID == receptor.ID()
	})

	require.Eventually(t, func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}, time.Second, 20*time.Millisecond)
}

func TestHandleStreamRejectsClosedHub(t *testing.T) {
	mn, h1, h2 := newMockHosts(t)
	defer mn.Close()

	installDiscardHandler(h2, testProtocol)

	hub, err := New(h1, Config{ProtocolID: testProtocol})
	require.NoError(t, err)
	defer hub.Close()

	stream := mustOpenStream(t, h1, h2.ID())
	tracked := &trackingStream{Stream: stream}

	markHubClosed(hub)
	hub.handleStream(tracked)

	require.True(t, tracked.resetCalled)
}

func TestHandleEventOverflowNilReceptorIsNoop(t *testing.T) {
	mn, h1, _ := newMockHosts(t)
	defer mn.Close()

	hub := newManualHub(t, h1, Config{ProtocolID: testProtocol})
	hub.handleEventOverflow(Event{Kind: EventKindDataReceived, PeerID: peer.ID("missing")})
}

func TestTransportDetailsAndHelperEdgePaths(t *testing.T) {
	mn, h1, h2 := newMockHosts(t)
	defer mn.Close()

	installDiscardHandler(h2, testProtocol)

	stream := mustOpenStream(t, h1, h2.ID())
	baseConn := stream.Conn()
	baseState := baseConn.ConnState()

	wrappedConn := connWrapper{
		Conn:     baseConn,
		hasState: true,
		state:    network.ConnectionState{Transport: "bogus", Security: baseState.Security, StreamMultiplexer: baseState.StreamMultiplexer},
		asResult: false,
	}
	details := buildTransportDetails(wrappedConn)
	require.Equal(t, addressFamilyFromMultiaddr(baseConn.RemoteMultiaddr()), details.AddressFamily)
	require.Equal(t, protocolStack(baseConn.RemoteMultiaddr()), details.ProtocolStack)
	require.False(t, details.DetailedMetricsAvailable)

	require.Empty(t, buildTransportDetails(nil))
	require.Empty(t, addressFamilyFromMultiaddr(nil))
	require.Equal(t, "ip4", addressFamilyFromMultiaddr(ma.StringCast("/ip4/127.0.0.1/tcp/4001")))
	require.Equal(t, "ip6", addressFamilyFromMultiaddr(ma.StringCast("/ip6/::1/tcp/4001")))
	require.True(t, multiaddrHasProtocol(ma.StringCast("/ip4/127.0.0.1/tcp/4001"), ma.P_TCP))
	require.False(t, multiaddrHasProtocol(nil, ma.P_TCP))
	require.False(t, multiaddrHasProtocol(ma.StringCast("/dns4/example.com/tcp/80"), ma.P_UDP))

	require.Nil(t, func() *QUICTransportDetails {
		details, ok := extractQUICDetails(wrappedConn)
		require.False(t, ok)
		return details
	}())
	require.Nil(t, func() *WebTransportTransportDetails {
		details, ok := extractWebTransportDetails(wrappedConn)
		require.False(t, ok)
		return details
	}())
	require.Nil(t, func() *WebRTCTransportDetails {
		details, ok := extractWebRTCDetails(wrappedConn)
		require.False(t, ok)
		return details
	}())
}

func TestSelectSnapshotConnPrefersActiveStreamAndNewestConn(t *testing.T) {
	mn, h1, h2 := newMockHosts(t)
	defer mn.Close()

	installDiscardHandler(h2, testProtocol)

	hub := newManualHub(t, h1, Config{ProtocolID: testProtocol})
	defer hub.Close()

	receptor := newReceptor(hub, ReceptorID("select"), peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()})
	insertReceptor(hub, receptor)

	first := mustOpenStream(t, h1, h2.ID())
	second := mustOpenStream(t, h1, h2.ID())

	firstConn := connWrapper{
		Conn:    first.Conn(),
		hasStat: true,
		stat:    network.ConnStats{Stats: network.Stats{Opened: time.Unix(1, 0)}},
	}
	secondConn := connWrapper{
		Conn:    second.Conn(),
		hasStat: true,
		stat:    network.ConnStats{Stats: network.Stats{Opened: time.Unix(2, 0)}},
	}

	require.Equal(t, secondConn.ID(), selectSnapshotConn(nil, []network.Conn{firstConn, secondConn}).ID())

	tracked := &trackingStream{Stream: first}
	setReceptorStream(receptor, tracked, network.DirOutbound)
	require.Equal(t, tracked.Conn().ID(), selectSnapshotConn(tracked, nil).ID())
}

func TestCloseHandlesEmptyHubAndIsIdempotent(t *testing.T) {
	mn, h1, _ := newMockHosts(t)
	defer mn.Close()

	hub := newManualHub(t, h1, Config{ProtocolID: testProtocol})
	require.NoError(t, hub.Close())
	require.NoError(t, hub.Close())
}

func TestRunConnectednessLoopIgnoresUnknownEvents(t *testing.T) {
	mn, h1, _ := newMockHosts(t)
	defer mn.Close()

	hub := newManualHub(t, h1, Config{ProtocolID: testProtocol})
	sub := &fakeSubscription{ch: make(chan any, 2), name: "unknown-events"}
	hub.connectednessSub = sub

	done := make(chan struct{})
	go func() {
		hub.runConnectednessLoop()
		close(done)
	}()

	sub.ch <- struct{}{}
	close(sub.ch)

	require.Eventually(t, func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}, time.Second, 20*time.Millisecond)
}

func newManualHub(t testing.TB, h host.Host, cfg Config) *Hub {
	t.Helper()

	normalized, err := normalizeConfig(cfg)
	require.NoError(t, err)

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
	return hub
}

func insertReceptor(hub *Hub, receptor *Receptor) {
	hub.mu.Lock()
	hub.receptorsByID[receptor.id] = receptor
	hub.receptorsByPeer[receptor.target.ID] = receptor
	hub.mu.Unlock()
}

func setReceptorStream(receptor *Receptor, stream network.Stream, direction network.Direction) {
	receptor.mu.Lock()
	receptor.activeStream = stream
	receptor.activeDirection = direction
	receptor.mu.Unlock()
}

func mustOpenStream(t testing.TB, src host.Host, dst peer.ID) network.Stream {
	t.Helper()

	stream, err := src.NewStream(context.Background(), dst, testProtocol)
	require.NoError(t, err)
	return stream
}

func oppositeDirection(direction network.Direction) network.Direction {
	switch direction {
	case network.DirInbound:
		return network.DirOutbound
	case network.DirOutbound:
		return network.DirInbound
	default:
		return network.DirUnknown
	}
}

func markHubClosed(hub *Hub) {
	hub.lifecycle.Store(uint32(hubStateClosed))
	hub.publishMu.Lock()
	hub.closed = true
	hub.publishMu.Unlock()
}

type trackingStream struct {
	network.Stream
	resetCalled      bool
	resetErr         error
	writeDeadlineErr error
}

func (s *trackingStream) Reset() error {
	s.resetCalled = true
	underlyingErr := s.Stream.Reset()
	if s.resetErr != nil {
		return s.resetErr
	}
	return underlyingErr
}

func (s *trackingStream) SetWriteDeadline(deadline time.Time) error {
	if s.writeDeadlineErr != nil {
		return s.writeDeadlineErr
	}
	return s.Stream.SetWriteDeadline(deadline)
}

type connWrapper struct {
	network.Conn
	hasState bool
	state    network.ConnectionState
	hasStat  bool
	stat     network.ConnStats
	asResult bool
}

func (c connWrapper) As(target any) bool {
	return c.asResult
}

func (c connWrapper) ConnState() network.ConnectionState {
	if c.hasState {
		return c.state
	}
	return c.Conn.ConnState()
}

func (c connWrapper) Stat() network.ConnStats {
	if c.hasStat {
		return c.stat
	}
	return c.Conn.Stat()
}

type fakeSubscription struct {
	ch   chan any
	name string
	once sync.Once
}

func (s *fakeSubscription) Out() <-chan any {
	return s.ch
}

func (s *fakeSubscription) Name() string {
	return s.name
}

func (s *fakeSubscription) Close() error {
	s.once.Do(func() {
		defer func() {
			_ = recover()
		}()
		close(s.ch)
	})
	return nil
}
