package discovery

import (
	"context"
	"math/rand"
	"testing"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	ma "github.com/multiformats/go-multiaddr"
)

func TestRelayDiscoverySelectRelaysAcrossModes(t *testing.T) {
	t.Parallel()

	modes := []string{
		selectionModeRTT,
		selectionModeRandom,
		selectionModeHybrid,
		selectionModeLOR,
		selectionModeSingleCircle,
		selectionModeMultipleCircle,
		selectionModeRegionalMixnet,
	}

	for _, mode := range modes {
		rd := NewRelayDiscovery("mixnet", 3, mode, 0.25)
		rd.rng = rand.New(rand.NewSource(1))

		selected, err := rd.SelectRelays(context.Background(), testRelays(6))
		if err != nil {
			t.Fatalf("SelectRelays(%s) error = %v", mode, err)
		}
		if len(selected) != 3 {
			t.Fatalf("SelectRelays(%s) len = %d, want 3", mode, len(selected))
		}
		assertUniqueDiscoveryRelays(t, selected)
	}
}

func TestRelayDiscoveryFindRelaysAndLatencyPaths(t *testing.T) {
	h1, err := libp2p.New()
	if err != nil {
		t.Fatalf("libp2p.New() error = %v", err)
	}
	t.Cleanup(func() { _ = h1.Close() })

	h2, err := libp2p.New()
	if err != nil {
		t.Fatalf("libp2p.New() error = %v", err)
	}
	t.Cleanup(func() { _ = h2.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	info := peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()}
	h1.Peerstore().AddProtocols(h2.ID(), protocol.ID("mixnet"))
	if err := h1.Connect(ctx, info); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	rd := NewRelayDiscoveryWithHost(h1, "mixnet", 1, selectionModeRTT, 0)
	found, err := rd.FindRelays(ctx, []peer.AddrInfo{{ID: h2.ID(), Addrs: h2.Addrs()}}, 1, 1)
	if err != nil {
		t.Fatalf("FindRelays() error = %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("FindRelays() len = %d, want 1", len(found))
	}
	if found[0].PeerID != h2.ID() {
		t.Fatalf("FindRelays() selected %s, want %s", found[0].PeerID, h2.ID())
	}

	measureOnly := NewRelayDiscovery("mixnet", 1, selectionModeRTT, 0)
	if _, err := measureOnly.measureRTTToPeer(ctx, info); err == nil {
		t.Fatal("measureRTTToPeer() expected error without ping service")
	}

	candidates := []peer.AddrInfo{
		{ID: peer.ID("relay-a"), Addrs: []ma.Multiaddr{ma.StringCast("/ip4/127.0.0.1/tcp/1")}},
		{ID: peer.ID("relay-b"), Addrs: []ma.Multiaddr{ma.StringCast("/ip4/127.0.0.1/tcp/2")}},
	}
	rdNoHost := NewRelayDiscovery("mixnet", 1, selectionModeRTT, 0)
	sorted, err := rdNoHost.sortedRelaysByLatency(ctx, candidates, 1, true)
	if err != nil {
		t.Fatalf("sortedRelaysByLatency() error = %v", err)
	}
	if len(sorted) != 2 || sorted[0].Latency != defaultLatency {
		t.Fatalf("sortedRelaysByLatency() = %#v", sorted)
	}
}

func TestRelayDiscoveryWeightedAndHelperFunctions(t *testing.T) {
	t.Parallel()

	rd := NewRelayDiscovery("mixnet", 4, selectionModeHybrid, 0.25)
	rd.rng = rand.New(rand.NewSource(2))

	peers := testAddrInfos(6)
	selected, err := rd.SelectRelaysForCircuit(context.Background(), peers, 4, 0.25)
	if err != nil {
		t.Fatalf("SelectRelaysForCircuit() error = %v", err)
	}
	if len(selected) != 4 {
		t.Fatalf("SelectRelaysForCircuit() len = %d, want 4", len(selected))
	}
	assertUniqueDiscoveryRelays(t, selected)

	random := rd.randomRelaySample(sortedRelayCandidates(relayInfosFromAddrInfos(peers)), 2)
	if len(random) != 2 {
		t.Fatalf("randomRelaySample() len = %d, want 2", len(random))
	}
	if got := rd.randomIntn(5); got < 0 || got >= 5 {
		t.Fatalf("randomIntn() = %d, want within range", got)
	}
	if got := rd.randomFloat64(); got < 0 || got >= 1 {
		t.Fatalf("randomFloat64() = %f, want within range", got)
	}

	if got := minInt(2, 4); got != 2 {
		t.Fatalf("minInt() = %d, want 2", got)
	}
	if got := maxInt(2, 4); got != 4 {
		t.Fatalf("maxInt() = %d, want 4", got)
	}

	if got := FilterByExclusion(peers, peers[0].ID); len(got) != len(peers)-1 {
		t.Fatalf("FilterByExclusion() len = %d", len(got))
	}

	relays := relayInfosFromAddrInfos(peers)
	SortByLatency(relays)
	if relays[0].Latency > relays[len(relays)-1].Latency {
		t.Fatal("SortByLatency() did not order by latency")
	}
}

func TestRelayDiscoveryCircleHelpers(t *testing.T) {
	t.Parallel()

	relays := testRelays(9)
	circles := buildLatencyCircles(relays, 3)
	if len(circles) != 3 {
		t.Fatalf("buildLatencyCircles() len = %d, want 3", len(circles))
	}
	layout, err := selectCircuitLayout(circles, relays, 3, 2, false)
	if err != nil {
		t.Fatalf("selectCircuitLayout() error = %v", err)
	}
	if len(layout) != 6 {
		t.Fatalf("selectCircuitLayout() len = %d, want 6", len(layout))
	}
	regional, err := selectRegionalLayout(relays, 3, 2)
	if err != nil {
		t.Fatalf("selectRegionalLayout() error = %v", err)
	}
	if len(regional) != 6 {
		t.Fatalf("selectRegionalLayout() len = %d, want 6", len(regional))
	}
	if _, ok := pickUnusedRelayFromCircles(circles, []int{0, 1}, map[peer.ID]struct{}{}); !ok {
		t.Fatal("pickUnusedRelayFromCircles() should select a relay")
	}
	if _, ok := pickUnusedRelay(relays, map[peer.ID]struct{}{relays[0].PeerID: {}}); !ok {
		t.Fatal("pickUnusedRelay() should select a relay")
	}
	if got := orderedCircleIndices(3, 1, 2, 3, true); len(got) != 3 {
		t.Fatalf("orderedCircleIndices() len = %d, want 3", len(got))
	}
}

func TestRelayDiscoveryNormalizationAndSampling(t *testing.T) {
	t.Parallel()

	rd := NewRelayDiscovery("mixnet", 2, selectionModeRTT, 0.5)
	rd.rng = rand.New(rand.NewSource(3))

	candidates := []RelayInfo{
		{PeerID: peer.ID("peer-b"), Latency: 0},
		{PeerID: peer.ID("peer-a"), Latency: 0},
		{PeerID: peer.ID("peer-a"), Latency: time.Second},
	}
	sorted := sortedRelayCandidates(candidates)
	if len(sorted) != 2 {
		t.Fatalf("sortedRelayCandidates() len = %d, want 2", len(sorted))
	}
	if sorted[0].Latency != defaultLatency {
		t.Fatalf("sortedRelayCandidates() default latency not applied: %#v", sorted[0])
	}

	if got := rd.latencyCandidatePool(testAddrInfos(5), 2, false); len(got) != 2 {
		t.Fatalf("latencyCandidatePool() len = %d, want 2", len(got))
	}
	if got := rd.sampleFromPool(testAddrInfos(2)); len(got) != 2 {
		t.Fatalf("sampleFromPool() len = %d, want 2", len(got))
	}
	if got := rd.randomSample(testAddrInfos(2), 1); len(got) != 1 {
		t.Fatalf("randomSample() len = %d, want 1", len(got))
	}
}

func testAddrInfos(count int) []peer.AddrInfo {
	peers := make([]peer.AddrInfo, 0, count)
	for i := 0; i < count; i++ {
		id := peer.ID("peer-" + string(rune('a'+i)))
		peers = append(peers, peer.AddrInfo{ID: id, Addrs: []ma.Multiaddr{ma.StringCast("/ip4/127.0.0.1/tcp/1")}})
	}
	return peers
}

func relayInfosFromAddrInfos(peers []peer.AddrInfo) []RelayInfo {
	relays := make([]RelayInfo, 0, len(peers))
	for i, p := range peers {
		relays = append(relays, RelayInfo{PeerID: p.ID, AddrInfo: p, Latency: time.Duration(i+1) * time.Millisecond, Available: true})
	}
	return relays
}

func assertUniqueDiscoveryRelays(t *testing.T, relays []RelayInfo) {
	t.Helper()

	seen := make(map[peer.ID]struct{}, len(relays))
	for _, relay := range relays {
		if _, ok := seen[relay.PeerID]; ok {
			t.Fatalf("relay %s selected more than once", relay.PeerID)
		}
		seen[relay.PeerID] = struct{}{}
	}
}
