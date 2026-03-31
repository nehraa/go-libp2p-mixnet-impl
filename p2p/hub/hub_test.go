package hub

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	mocknet "github.com/libp2p/go-libp2p/p2p/net/mock"

	"github.com/stretchr/testify/require"
)

const testProtocol = protocol.ID("/hub/test/1.0.0")

func TestNewRejectsInvalidConfig(t *testing.T) {
	mn, h1, _ := newMockHosts(t)
	defer mn.Close()

	_, err := New(h1, Config{})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidConfig)
}

func TestNewRejectsInvalidConfigValues(t *testing.T) {
	mn, h1, _ := newMockHosts(t)
	defer mn.Close()

	testCases := []struct {
		name string
		cfg  Config
	}{
		{name: "negative ping interval", cfg: Config{ProtocolID: testProtocol, PingInterval: -time.Second}},
		{name: "non-positive ping timeout", cfg: Config{ProtocolID: testProtocol, PingTimeout: -time.Second}},
		{name: "negative event buffer", cfg: Config{ProtocolID: testProtocol, EventBufferSize: -1}},
		{name: "negative metrics buffer", cfg: Config{ProtocolID: testProtocol, MetricsBufferSize: -1}},
		{name: "negative read buffer", cfg: Config{ProtocolID: testProtocol, ReadBufferSize: -1}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(h1, tc.cfg)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrInvalidConfig)
		})
	}
}

func TestCreateReceptorRejectsDuplicatePeerBinding(t *testing.T) {
	mn, h1, h2 := newMockHosts(t)
	defer mn.Close()

	installDiscardHandler(h2, testProtocol)

	hub, err := New(h1, Config{ProtocolID: testProtocol})
	require.NoError(t, err)
	defer hub.Close()

	receptor, err := hub.CreateReceptor(context.Background(), peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()})
	require.NotNil(t, receptor)
	require.NoError(t, err)

	duplicate, err := hub.CreateReceptor(context.Background(), peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()})
	require.Nil(t, duplicate)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrDuplicatePeerBinding)
}

func TestReceptorPeerAndSnapshotsExposeBoundPeer(t *testing.T) {
	mn, h1, h2 := newMockHosts(t)
	defer mn.Close()

	hub1, err := New(h1, Config{ProtocolID: testProtocol})
	require.NoError(t, err)
	defer hub1.Close()

	hub2, err := New(h2, Config{ProtocolID: testProtocol})
	require.NoError(t, err)
	defer hub2.Close()

	receptor1, _ := createPairedReceptors(t, hub1, hub2, h1, h2)
	require.Equal(t, h2.ID(), receptor1.Peer())

	snapshots := hub1.Snapshots()
	require.Len(t, snapshots, 1)
	require.Equal(t, receptor1.ID(), snapshots[0].ReceptorID)
	require.Equal(t, h2.ID(), snapshots[0].PeerID)
}

func TestCreateReceptorRejectsSelfBinding(t *testing.T) {
	mn, h1, _ := newMockHosts(t)
	defer mn.Close()

	hub, err := New(h1, Config{ProtocolID: testProtocol})
	require.NoError(t, err)
	defer hub.Close()

	receptor, err := hub.CreateReceptor(context.Background(), peer.AddrInfo{ID: h1.ID(), Addrs: h1.Addrs()})
	require.Nil(t, receptor)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrSelfBinding)
}

func TestCreateReceptorAndReceiveData(t *testing.T) {
	mn, h1, h2 := newMockHosts(t)
	defer mn.Close()

	hub1, err := New(h1, Config{ProtocolID: testProtocol})
	require.NoError(t, err)
	defer hub1.Close()

	hub2, err := New(h2, Config{ProtocolID: testProtocol})
	require.NoError(t, err)
	defer hub2.Close()

	receptor1, receptor2 := createPairedReceptors(t, hub1, hub2, h1, h2)

	payload := []byte("hello-receptor")
	var received Event

	require.Eventually(t, func() bool {
		if _, sendErr := receptor1.Send(context.Background(), payload); sendErr != nil {
			_ = hub1.OpenStream(context.Background(), receptor1.ID())
			return false
		}

		evt, ok := collectMatchingEvent(hub2.Events(), func(evt Event) bool {
			return evt.Kind == EventKindDataReceived &&
				evt.ReceptorID == receptor2.ID() &&
				bytes.Equal(evt.Data, payload)
		})
		if ok {
			received = evt
		}
		return ok
	}, 2*time.Second, 20*time.Millisecond)

	require.True(t, received.IsFirstPacket)
	require.Equal(t, payload, received.Data)
	require.Equal(t, uint64(len(payload)), received.Snapshot.BytesReceived)
}

func TestCreateReceptorConcurrentlyReturnsBindings(t *testing.T) {
	mn, h1, h2 := newMockHosts(t)
	defer mn.Close()

	hub1, err := New(h1, Config{ProtocolID: testProtocol})
	require.NoError(t, err)
	defer hub1.Close()

	hub2, err := New(h2, Config{ProtocolID: testProtocol})
	require.NoError(t, err)
	defer hub2.Close()

	resultCh := make(chan *Receptor, 2)
	go func() {
		receptor, _ := hub1.CreateReceptor(context.Background(), peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()})
		resultCh <- receptor
	}()
	go func() {
		receptor, _ := hub2.CreateReceptor(context.Background(), peer.AddrInfo{ID: h1.ID(), Addrs: h1.Addrs()})
		resultCh <- receptor
	}()

	receptor1 := <-resultCh
	receptor2 := <-resultCh
	require.NotNil(t, receptor1)
	require.NotNil(t, receptor2)

	_, err = hub1.Snapshot(receptor1.ID())
	require.NoError(t, err)
	_, err = hub2.Snapshot(receptor2.ID())
	require.NoError(t, err)
}

func TestHandleStreamRejectsUnknownPeer(t *testing.T) {
	mn, h1, h2 := newMockHosts(t)
	defer mn.Close()

	hub, err := New(h1, Config{ProtocolID: testProtocol})
	require.NoError(t, err)
	defer hub.Close()

	stream, err := h2.NewStream(context.Background(), h1.ID(), testProtocol)
	if err == nil {
		defer stream.Close()
		_, _ = stream.Write([]byte("x"))
	}

	errEvent := waitForEvent(t, hub.Events(), 2*time.Second, func(evt Event) bool {
		return evt.Kind == EventKindError && evt.PeerID == h2.ID()
	})
	require.Error(t, errEvent.Err)
}

func TestResetStreamAndRemoveReceptor(t *testing.T) {
	mn, h1, h2 := newMockHosts(t)
	defer mn.Close()

	hub1, err := New(h1, Config{ProtocolID: testProtocol})
	require.NoError(t, err)
	defer hub1.Close()

	hub2, err := New(h2, Config{ProtocolID: testProtocol})
	require.NoError(t, err)
	defer hub2.Close()

	receptor1, receptor2 := createPairedReceptors(t, hub1, hub2, h1, h2)

	require.NoError(t, hub1.ResetStream(receptor1.ID()))
	snapshot, err := hub1.Snapshot(receptor1.ID())
	require.NoError(t, err)
	require.False(t, snapshot.HasActiveStream)

	waitForActiveStream(t, hub1, receptor1.ID(), func() { _ = hub1.OpenStream(context.Background(), receptor1.ID()) })
	waitForActiveStream(t, hub2, receptor2.ID(), func() { _ = hub2.OpenStream(context.Background(), receptor2.ID()) })

	require.NoError(t, hub1.RemoveReceptor(receptor1.ID()))
	_, err = hub1.Snapshot(receptor1.ID())
	require.Error(t, err)
	require.ErrorIs(t, err, ErrReceptorNotFound)
}

func TestPeerOfflineEvent(t *testing.T) {
	mn, h1, h2 := newMockHosts(t)
	defer mn.Close()

	hub1, err := New(h1, Config{ProtocolID: testProtocol})
	require.NoError(t, err)
	defer hub1.Close()

	hub2, err := New(h2, Config{ProtocolID: testProtocol})
	require.NoError(t, err)
	defer hub2.Close()

	receptor1, receptor2 := createPairedReceptors(t, hub1, hub2, h1, h2)
	waitForActiveStream(t, hub1, receptor1.ID(), func() {})
	waitForActiveStream(t, hub2, receptor2.ID(), func() {})

	require.NoError(t, mn.DisconnectPeers(h1.ID(), h2.ID()))

	offline := waitForEvent(t, hub1.Events(), 2*time.Second, func(evt Event) bool {
		return evt.Kind == EventKindPeerOffline && evt.ReceptorID == receptor1.ID()
	})
	require.Equal(t, h2.ID(), offline.PeerID)
	require.False(t, offline.Snapshot.HasActiveStream)
}

func TestCloseEmitsTerminalLifecycleEvents(t *testing.T) {
	mn, h1, h2 := newMockHosts(t)
	defer mn.Close()

	hub1, err := New(h1, Config{ProtocolID: testProtocol})
	require.NoError(t, err)

	hub2, err := New(h2, Config{ProtocolID: testProtocol})
	require.NoError(t, err)
	defer hub2.Close()

	receptor1, _ := createPairedReceptors(t, hub1, hub2, h1, h2)
	drainEvents(hub1.Events())

	collectedEvents := make(chan []Event, 1)
	go func() {
		events := make([]Event, 0, 4)
		for evt := range hub1.Events() {
			events = append(events, evt)
		}
		collectedEvents <- events
	}()

	require.NoError(t, hub1.Close())
	events := <-collectedEvents

	require.Contains(t, eventKindsForReceptor(events, receptor1.ID()), EventKindStreamClosed)
	require.Contains(t, eventKindsForReceptor(events, receptor1.ID()), EventKindReceptorRemoved)
}

func createPairedReceptors(t *testing.T, hub1, hub2 *Hub, h1, h2 host.Host) (*Receptor, *Receptor) {
	t.Helper()

	receptor1, err := hub1.CreateReceptor(context.Background(), peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()})
	require.NotNil(t, receptor1)
	if err != nil && !errors.Is(err, ErrActiveStreamExists) {
		t.Logf("hub1 initial create returned: %v", err)
	}

	receptor2, err := hub2.CreateReceptor(context.Background(), peer.AddrInfo{ID: h1.ID(), Addrs: h1.Addrs()})
	require.NotNil(t, receptor2)
	if err != nil && !errors.Is(err, ErrActiveStreamExists) {
		t.Logf("hub2 initial create returned: %v", err)
	}

	if err := hub1.ResetStream(receptor1.ID()); err != nil && !errors.Is(err, ErrNoActiveStream) {
		require.NoError(t, err)
	}
	if err := hub2.ResetStream(receptor2.ID()); err != nil && !errors.Is(err, ErrNoActiveStream) {
		require.NoError(t, err)
	}

	waitForNoActiveStream(t, hub1, receptor1.ID())
	waitForNoActiveStream(t, hub2, receptor2.ID())

	initiatorHub := hub1
	initiatorReceptor := receptor1
	acceptorHub := hub2
	acceptorReceptor := receptor2
	if receptor1.preferredDirection() != network.DirOutbound {
		initiatorHub = hub2
		initiatorReceptor = receptor2
		acceptorHub = hub1
		acceptorReceptor = receptor1
	}

	waitForActiveStream(t, initiatorHub, initiatorReceptor.ID(), func() {
		_ = initiatorHub.OpenStream(context.Background(), initiatorReceptor.ID())
	})
	waitForActiveStream(t, acceptorHub, acceptorReceptor.ID(), func() {})
	return receptor1, receptor2
}

func installDiscardHandler(h host.Host, pid protocol.ID) {
	h.SetStreamHandler(pid, func(stream network.Stream) {
		go func() {
			defer stream.Close()
			_, _ = io.Copy(io.Discard, stream)
		}()
	})
}

func waitForActiveStream(t *testing.T, hub *Hub, id ReceptorID, tick func()) Snapshot {
	t.Helper()

	var snapshot Snapshot
	require.Eventually(t, func() bool {
		tick()
		current, err := hub.Snapshot(id)
		if err != nil {
			return false
		}
		snapshot = current
		return snapshot.HasActiveStream
	}, 2*time.Second, 20*time.Millisecond)
	return snapshot
}

func waitForNoActiveStream(t *testing.T, hub *Hub, id ReceptorID) Snapshot {
	t.Helper()

	var snapshot Snapshot
	require.Eventually(t, func() bool {
		current, err := hub.Snapshot(id)
		if err != nil {
			return false
		}
		snapshot = current
		return !snapshot.HasActiveStream
	}, 2*time.Second, 20*time.Millisecond)
	return snapshot
}

func waitForEvent(t *testing.T, events <-chan Event, timeout time.Duration, predicate func(Event) bool) Event {
	t.Helper()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case evt, ok := <-events:
			if !ok {
				t.Fatal("event channel closed before expected event")
			}
			if predicate(evt) {
				return evt
			}
		case <-timer.C:
			t.Fatal("timed out waiting for event")
		}
	}
}

func collectMatchingEvent(events <-chan Event, predicate func(Event) bool) (Event, bool) {
	for {
		select {
		case evt, ok := <-events:
			if !ok {
				return Event{}, false
			}
			if predicate(evt) {
				return evt, true
			}
		default:
			return Event{}, false
		}
	}
}

func eventKindsForReceptor(events []Event, id ReceptorID) []EventKind {
	kinds := make([]EventKind, 0, len(events))
	for _, evt := range events {
		if evt.ReceptorID == id {
			kinds = append(kinds, evt.Kind)
		}
	}
	return kinds
}

func newMockHosts(t *testing.T) (mocknet.Mocknet, host.Host, host.Host) {
	t.Helper()

	mn, err := mocknet.FullMeshConnected(2)
	require.NoError(t, err)

	peers := mn.Peers()
	require.Len(t, peers, 2)
	return mn, mn.Host(peers[0]), mn.Host(peers[1])
}
