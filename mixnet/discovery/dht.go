// Package discovery handles the discovery and selection of mixnet relay nodes.
package discovery

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	ping "github.com/libp2p/go-libp2p/p2p/protocol/ping"
)

// RelayDiscovery provides mechanisms for discovering and selecting mixnet relays.
type RelayDiscovery struct {
	protocolID       string
	samplingSize     int
	selectionMode    string
	randomnessFactor float64
	host             host.Host
	pingService      *ping.PingService
	rng              *rand.Rand
	rngMu            sync.Mutex
}

const (
	selectionModeRTT            = "rtt"
	selectionModeRandom         = "random"
	selectionModeHybrid         = "hybrid"
	selectionModeLOR            = "lor"
	selectionModeSingleCircle   = "single-circle"
	selectionModeMultipleCircle = "multiple-circle"
	selectionModeRegionalMixnet = "regional-mixnet"
	defaultLatency              = 100 * time.Millisecond
)

func normalizeSelectionMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "default", selectionModeRTT:
		return selectionModeRTT
	case selectionModeRandom:
		return selectionModeRandom
	case selectionModeHybrid:
		return selectionModeHybrid
	case selectionModeLOR, "leave-one-random", "leave_one_random":
		return selectionModeLOR
	case "sc", selectionModeSingleCircle, "single_circle", "singlecircle":
		return selectionModeSingleCircle
	case "mc", selectionModeMultipleCircle, "multiple_circle", "multiplecircle":
		return selectionModeMultipleCircle
	case "rm", selectionModeRegionalMixnet, "regional_mixnet", "regionalmixnet":
		return selectionModeRegionalMixnet
	default:
		return selectionModeRTT
	}
}

// RelayInfo contains information about a candidate relay node discovered in the network.
type RelayInfo struct {
	// PeerID is the unique ID of the relay peer.
	PeerID peer.ID
	// AddrInfo contains the addresses of the relay peer.
	AddrInfo peer.AddrInfo
	// Latency is the measured RTT to the relay.
	Latency time.Duration
	// Available indicates if the relay is currently considered reachable.
	Available bool
}

// NewRelayDiscovery creates a new RelayDiscovery instance with the specified parameters.
func NewRelayDiscovery(protocolID string, samplingSize int, selectionMode string, randomnessFactor float64) *RelayDiscovery {
	return &RelayDiscovery{
		protocolID:       protocolID,
		samplingSize:     samplingSize,
		selectionMode:    normalizeSelectionMode(selectionMode),
		randomnessFactor: randomnessFactor,
		rng:              newRand(),
	}
}

// NewRelayDiscoveryWithHost creates a RelayDiscovery instance that uses a libp2p host for RTT measurements.
func NewRelayDiscoveryWithHost(h host.Host, protocolID string, samplingSize int, selectionMode string, randomnessFactor float64) *RelayDiscovery {
	ps := ping.NewPingService(h)
	return &RelayDiscovery{
		protocolID:       protocolID,
		samplingSize:     samplingSize,
		selectionMode:    normalizeSelectionMode(selectionMode),
		randomnessFactor: randomnessFactor,
		host:             h,
		pingService:      ps,
		rng:              newRand(),
	}
}

// SelectRelays chooses a concrete subset of relays from already-discovered
// candidates using the configured selection strategy.
func (r *RelayDiscovery) SelectRelays(ctx context.Context, candidates []RelayInfo) ([]RelayInfo, error) {
	if len(candidates) == 0 {
		return nil, fmt.Errorf("insufficient relay peers: have 0, need 1")
	}

	count := r.samplingSize
	if count <= 0 || count > len(candidates) {
		count = len(candidates)
	}

	sorted := sortedRelayCandidates(candidates)
	if len(sorted) < count {
		return nil, fmt.Errorf("could not select enough relays: have %d, need %d", len(sorted), count)
	}

	switch normalizeSelectionMode(r.selectionMode) {
	case selectionModeRandom:
		return r.randomRelaySample(sorted, count), nil
	case selectionModeHybrid:
		window := minInt(len(sorted), maxInt(count, r.samplingSize))
		if window < count {
			window = count
		}
		return r.randomRelaySample(sorted[:window], count), nil
	case selectionModeLOR:
		window := minInt(len(sorted), maxInt(count+1, count*2))
		pool := append([]RelayInfo(nil), sorted[:window]...)
		if len(pool) > count {
			drop := r.randomIntn(len(pool))
			pool = append(pool[:drop], pool[drop+1:]...)
		}
		return takeUniqueRelays(pool, count)
	case selectionModeSingleCircle:
		return takeUniqueRelays(sorted, count)
	case selectionModeMultipleCircle:
		return selectCircuitLayout(buildLatencyCircles(sorted, 3), sorted, 1, count, false)
	case selectionModeRegionalMixnet:
		return selectRegionalLayout(sorted, 1, count)
	default:
		return takeUniqueRelays(sorted, count)
	}
}

// FindRelays discovers potential relay nodes and selects them based on selection mode.
func (r *RelayDiscovery) FindRelays(ctx context.Context, peers []peer.AddrInfo, hopCount, circuitCount int) ([]RelayInfo, error) {
	filtered := r.filterPeers(peers)
	required := hopCount * circuitCount
	if len(filtered) < required {
		return nil, fmt.Errorf("insufficient relay peers: have %d, need %d", len(filtered), required)
	}

	switch normalizeSelectionMode(r.selectionMode) {
	case selectionModeRandom:
		return r.selectRandom(filtered, required)
	case selectionModeHybrid:
		return r.selectHybrid(ctx, filtered, required, hopCount, circuitCount, r.randomnessFactor)
	case selectionModeLOR:
		return r.selectLeaveOneRandom(ctx, filtered, required)
	case selectionModeSingleCircle:
		return r.selectSingleCircle(ctx, filtered, required)
	case selectionModeMultipleCircle:
		return r.selectMultipleCircle(ctx, filtered, required, hopCount, circuitCount)
	case selectionModeRegionalMixnet:
		return r.selectRegionalMixnet(ctx, filtered, required, hopCount, circuitCount)
	default:
		return r.selectByRTT(ctx, filtered, required)
	}
}

func (r *RelayDiscovery) filterPeers(peers []peer.AddrInfo) []peer.AddrInfo {
	var result []peer.AddrInfo
	for _, p := range peers {
		// Check protocol support if host is available
		if r.host != nil {
			supported, err := r.host.Peerstore().SupportsProtocols(p.ID, protocol.ID(r.protocolID))
			if err != nil || len(supported) == 0 {
				continue // Skip peers without mixnet protocol
			}
		}
		if len(p.Addrs) > 0 {
			result = append(result, p)
		}
	}
	return result
}

func (r *RelayDiscovery) selectRandom(peers []peer.AddrInfo, count int) ([]RelayInfo, error) {
	if len(peers) < count {
		return nil, fmt.Errorf("insufficient peers: have %d, need %d", len(peers), count)
	}

	shuffled := make([]peer.AddrInfo, len(peers))
	copy(shuffled, peers)
	r.shuffleAddrInfos(shuffled)
	result := make([]RelayInfo, count)
	for i := 0; i < count; i++ {
		result[i] = RelayInfo{
			PeerID:    shuffled[i].ID,
			AddrInfo:  shuffled[i],
			Available: true,
		}
	}
	return result, nil
}

func (r *RelayDiscovery) selectByRTT(ctx context.Context, peers []peer.AddrInfo, count int) ([]RelayInfo, error) {
	sorted, err := r.sortedRelaysByLatency(ctx, peers, count, false)
	if err != nil {
		return nil, err
	}
	return takeUniqueRelays(sorted, count)
}

func (r *RelayDiscovery) selectSingleCircle(ctx context.Context, peers []peer.AddrInfo, count int) ([]RelayInfo, error) {
	sorted, err := r.sortedRelaysByLatency(ctx, peers, count, true)
	if err != nil {
		return nil, err
	}
	return takeUniqueRelays(sorted, count)
}

func (r *RelayDiscovery) selectLeaveOneRandom(ctx context.Context, peers []peer.AddrInfo, count int) ([]RelayInfo, error) {
	sorted, err := r.sortedRelaysByLatency(ctx, peers, maxInt(count+1, count*2), false)
	if err != nil {
		return nil, err
	}
	if len(sorted) > count {
		window := minInt(len(sorted), maxInt(count+1, count*2))
		dropIndex := r.randomIntn(window)
		sorted = append(sorted[:dropIndex], sorted[dropIndex+1:]...)
	}
	return takeUniqueRelays(sorted, count)
}

func (r *RelayDiscovery) selectMultipleCircle(ctx context.Context, peers []peer.AddrInfo, required, hopCount, circuitCount int) ([]RelayInfo, error) {
	sorted, err := r.sortedRelaysByLatency(ctx, peers, maxInt(required*2, r.samplingSize), true)
	if err != nil {
		return nil, err
	}
	circles := buildLatencyCircles(sorted, 3)
	return selectCircuitLayout(circles, sorted, hopCount, circuitCount, false)
}

func (r *RelayDiscovery) selectRegionalMixnet(ctx context.Context, peers []peer.AddrInfo, required, hopCount, circuitCount int) ([]RelayInfo, error) {
	sorted, err := r.sortedRelaysByLatency(ctx, peers, maxInt(required*2, r.samplingSize), true)
	if err != nil {
		return nil, err
	}
	return selectRegionalLayout(sorted, hopCount, circuitCount)
}

func (r *RelayDiscovery) sortedRelaysByLatency(ctx context.Context, peers []peer.AddrInfo, minCandidates int, fullPool bool) ([]RelayInfo, error) {
	candidates := r.latencyCandidatePool(peers, minCandidates, fullPool)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("insufficient peers: have 0, need %d", minCandidates)
	}

	latencies, err := r.measureLatencies(ctx, candidates)
	if err != nil {
		return nil, err
	}

	sorted := make([]RelayInfo, 0, len(candidates))
	for _, p := range candidates {
		latency, ok := latencies[p.ID]
		if !ok || latency <= 0 {
			latency = defaultLatency
		}
		sorted = append(sorted, RelayInfo{
			PeerID:    p.ID,
			AddrInfo:  p,
			Latency:   latency,
			Available: ok && latencies[p.ID] > 0,
		})
	}

	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Latency == sorted[j].Latency {
			return sorted[i].PeerID.String() < sorted[j].PeerID.String()
		}
		return sorted[i].Latency < sorted[j].Latency
	})

	return sorted, nil
}

func (r *RelayDiscovery) latencyCandidatePool(peers []peer.AddrInfo, minCandidates int, fullPool bool) []peer.AddrInfo {
	if fullPool || len(peers) <= minCandidates {
		result := make([]peer.AddrInfo, len(peers))
		copy(result, peers)
		return result
	}
	target := minInt(len(peers), maxInt(minCandidates, r.samplingSize))
	if target <= 0 || target >= len(peers) {
		result := make([]peer.AddrInfo, len(peers))
		copy(result, peers)
		return result
	}
	return r.randomSample(peers, target)
}

func takeUniqueRelays(relays []RelayInfo, count int) ([]RelayInfo, error) {
	result := make([]RelayInfo, 0, count)
	used := make(map[peer.ID]struct{}, count)
	for _, relay := range relays {
		if _, ok := used[relay.PeerID]; ok {
			continue
		}
		used[relay.PeerID] = struct{}{}
		result = append(result, relay)
		if len(result) == count {
			return result, nil
		}
	}
	return nil, fmt.Errorf("could not select enough relays: have %d, need %d", len(result), count)
}

func sortedRelayCandidates(candidates []RelayInfo) []RelayInfo {
	normalized := make([]RelayInfo, 0, len(candidates))
	seen := make(map[peer.ID]struct{}, len(candidates))
	for _, candidate := range candidates {
		if candidate.PeerID == "" {
			candidate.PeerID = candidate.AddrInfo.ID
		}
		if candidate.PeerID == "" {
			continue
		}
		if candidate.AddrInfo.ID == "" {
			candidate.AddrInfo.ID = candidate.PeerID
		}
		if candidate.Latency <= 0 {
			candidate.Latency = defaultLatency
		}
		if _, ok := seen[candidate.PeerID]; ok {
			continue
		}
		seen[candidate.PeerID] = struct{}{}
		normalized = append(normalized, candidate)
	}

	sort.SliceStable(normalized, func(i, j int) bool {
		if normalized[i].Available != normalized[j].Available {
			return normalized[i].Available
		}
		if normalized[i].Latency == normalized[j].Latency {
			return normalized[i].PeerID.String() < normalized[j].PeerID.String()
		}
		return normalized[i].Latency < normalized[j].Latency
	})
	return normalized
}

func (r *RelayDiscovery) randomRelaySample(candidates []RelayInfo, count int) []RelayInfo {
	if count >= len(candidates) {
		out := make([]RelayInfo, len(candidates))
		copy(out, candidates)
		return out
	}
	shuffled := make([]RelayInfo, len(candidates))
	copy(shuffled, candidates)
	r.rngMu.Lock()
	defer r.rngMu.Unlock()
	if r.rng == nil {
		r.rng = newRand()
	}
	r.rng.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	return shuffled[:count]
}

func buildLatencyCircles(sorted []RelayInfo, circleCount int) [][]RelayInfo {
	if len(sorted) == 0 {
		return nil
	}
	if circleCount < 1 {
		circleCount = 1
	}
	if circleCount > len(sorted) {
		circleCount = len(sorted)
	}

	circles := make([][]RelayInfo, 0, circleCount)
	baseSize := len(sorted) / circleCount
	remainder := len(sorted) % circleCount
	start := 0
	for i := 0; i < circleCount; i++ {
		size := baseSize
		if remainder > 0 {
			size++
			remainder--
		}
		end := start + size
		if end > len(sorted) {
			end = len(sorted)
		}
		if end > start {
			circles = append(circles, sorted[start:end])
		}
		start = end
	}
	return circles
}

func selectCircuitLayout(circles [][]RelayInfo, fallback []RelayInfo, hopCount, circuitCount int, preferRemoteExit bool) ([]RelayInfo, error) {
	required := hopCount * circuitCount
	if required == 0 {
		return nil, nil
	}

	result := make([]RelayInfo, 0, required)
	used := make(map[peer.ID]struct{}, required)

	for circuit := 0; circuit < circuitCount; circuit++ {
		baseCircle := circuit % maxInt(1, len(circles))
		for hop := 0; hop < hopCount; hop++ {
			circleOrder := orderedCircleIndices(len(circles), baseCircle, hop, hopCount, preferRemoteExit)
			relay, ok := pickUnusedRelayFromCircles(circles, circleOrder, used)
			if !ok {
				relay, ok = pickUnusedRelay(fallback, used)
			}
			if !ok {
				return nil, fmt.Errorf("could not select enough relays: have %d, need %d", len(result), required)
			}
			used[relay.PeerID] = struct{}{}
			result = append(result, relay)
		}
	}

	return result, nil
}

func selectRegionalLayout(sorted []RelayInfo, hopCount, circuitCount int) ([]RelayInfo, error) {
	required := hopCount * circuitCount
	if required == 0 {
		return nil, nil
	}

	if len(sorted) < required {
		return nil, fmt.Errorf("could not select enough relays: have %d, need %d", len(sorted), required)
	}

	fastCount := len(sorted) / 2
	if fastCount < hopCount-1 {
		fastCount = minInt(len(sorted), maxInt(hopCount-1, 1))
	}
	if fastCount >= len(sorted) {
		fastCount = len(sorted) - 1
	}
	if fastCount <= 0 {
		return takeUniqueRelays(sorted, required)
	}

	fastPool := sorted[:fastCount]
	remotePool := sorted[fastCount:]
	result := make([]RelayInfo, 0, required)
	used := make(map[peer.ID]struct{}, required)

	for circuit := 0; circuit < circuitCount; circuit++ {
		for hop := 0; hop < hopCount; hop++ {
			pool := fastPool
			if hop == hopCount-1 && len(remotePool) > 0 {
				pool = remotePool
			}
			relay, ok := pickUnusedRelay(pool, used)
			if !ok {
				relay, ok = pickUnusedRelay(sorted, used)
			}
			if !ok {
				return nil, fmt.Errorf("could not select enough relays: have %d, need %d", len(result), required)
			}
			used[relay.PeerID] = struct{}{}
			result = append(result, relay)
		}
	}

	return result, nil
}

func orderedCircleIndices(circleCount, baseCircle, hop, hopCount int, preferRemoteExit bool) []int {
	if circleCount == 0 {
		return nil
	}

	order := make([]int, 0, circleCount)
	seen := make(map[int]struct{}, circleCount)
	if preferRemoteExit && hop == hopCount-1 {
		order = append(order, circleCount-1)
		seen[circleCount-1] = struct{}{}
	}
	start := baseCircle % circleCount
	for offset := 0; offset < circleCount; offset++ {
		idx := (start + offset) % circleCount
		if _, ok := seen[idx]; ok {
			continue
		}
		order = append(order, idx)
	}
	return order
}

func pickUnusedRelayFromCircles(circles [][]RelayInfo, order []int, used map[peer.ID]struct{}) (RelayInfo, bool) {
	for _, idx := range order {
		if idx < 0 || idx >= len(circles) {
			continue
		}
		if relay, ok := pickUnusedRelay(circles[idx], used); ok {
			return relay, true
		}
	}
	return RelayInfo{}, false
}

func pickUnusedRelay(candidates []RelayInfo, used map[peer.ID]struct{}) (RelayInfo, bool) {
	for _, candidate := range candidates {
		if _, ok := used[candidate.PeerID]; ok {
			continue
		}
		return candidate, true
	}
	return RelayInfo{}, false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (r *RelayDiscovery) shuffleAddrInfos(shuffled []peer.AddrInfo) {
	r.rngMu.Lock()
	defer r.rngMu.Unlock()
	if r.rng == nil {
		r.rng = newRand()
	}
	r.rng.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
}

func (r *RelayDiscovery) randomIntn(n int) int {
	if n <= 1 {
		return 0
	}
	r.rngMu.Lock()
	defer r.rngMu.Unlock()
	if r.rng == nil {
		r.rng = newRand()
	}
	return r.rng.Intn(n)
}

func (r *RelayDiscovery) randomFloat64() float64 {
	r.rngMu.Lock()
	defer r.rngMu.Unlock()
	if r.rng == nil {
		r.rng = newRand()
	}
	return r.rng.Float64()
}

func (r *RelayDiscovery) selectHybrid(ctx context.Context, peers []peer.AddrInfo, required, hopCount, circuitCount int, randomnessFactor float64) ([]RelayInfo, error) {
	sampleSize := r.samplingSize
	if sampleSize < required {
		sampleSize = required * 2
	}
	if sampleSize > len(peers) {
		sampleSize = len(peers)
	}

	sampled := r.randomSample(peers, sampleSize)
	latencies, err := r.measureLatencies(ctx, sampled)
	if err != nil {
		return nil, err
	}

	relays := r.buildCircuitsWithWeights(sampled, latencies, circuitCount, hopCount, randomnessFactor)
	if len(relays) < required {
		return nil, fmt.Errorf("could not select enough relays")
	}
	return relays, nil
}

func (r *RelayDiscovery) sampleFromPool(peers []peer.AddrInfo) []peer.AddrInfo {
	if r.samplingSize == 0 || len(peers) <= r.samplingSize {
		return peers
	}
	return r.randomSample(peers, r.samplingSize)
}

func (r *RelayDiscovery) randomSample(peers []peer.AddrInfo, k int) []peer.AddrInfo {
	if k >= len(peers) {
		result := make([]peer.AddrInfo, len(peers))
		copy(result, peers)
		return result
	}
	shuffled := make([]peer.AddrInfo, len(peers))
	copy(shuffled, peers)
	r.shuffleAddrInfos(shuffled)
	return shuffled[:k]
}

// measureLatencies measures RTT to all provided peers.
func (r *RelayDiscovery) measureLatencies(ctx context.Context, peers []peer.AddrInfo) (map[peer.ID]time.Duration, error) {
	result := make(map[peer.ID]time.Duration)

	if r.pingService == nil {
		// No host available: assign a uniform default so callers get a valid map.
		for _, p := range peers {
			result[p.ID] = defaultLatency
		}
		return result, nil
	}

	type resultChan struct {
		peerID  peer.ID
		latency time.Duration
		err     error
	}

	rc := make(chan resultChan, len(peers))

	maxConcurrent := 32
	if len(peers) < maxConcurrent {
		maxConcurrent = len(peers)
	}
	if maxConcurrent == 0 {
		return result, nil
	}

	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

loop:
	for _, p := range peers {
		select {
		case <-ctx.Done():
			break loop
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(addrInfo peer.AddrInfo) {
			defer wg.Done()
			defer func() { <-sem }()
			latency, err := r.measureRTTToPeer(ctx, addrInfo)
			rc <- resultChan{addrInfo.ID, latency, err}
		}(p)
	}

	go func() {
		wg.Wait()
		close(rc)
	}()

	var ctxErr error
	for res := range rc {
		if res.err == nil && res.latency > 0 {
			result[res.peerID] = res.latency
		}
		if ctxErr == nil && ctx.Err() != nil {
			ctxErr = fmt.Errorf("context cancelled during latency measurement")
		}
	}
	if ctxErr != nil {
		return result, ctxErr
	}
	return result, nil
}

func newRand() *rand.Rand {
	var seed int64
	if err := binary.Read(crand.Reader, binary.LittleEndian, &seed); err != nil {
		seed = time.Now().UnixNano()
	}
	return rand.New(rand.NewSource(seed))
}

// measureRTTToPeer measures round-trip time to a peer using the libp2p ping protocol.
func (r *RelayDiscovery) measureRTTToPeer(ctx context.Context, addrInfo peer.AddrInfo) (time.Duration, error) {
	if r.pingService == nil {
		return 0, fmt.Errorf("ping service not configured")
	}

	// Ensure we are connected before pinging.
	if r.host.Network().Connectedness(addrInfo.ID) != network.Connected {
		connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := r.host.Connect(connectCtx, addrInfo); err != nil {
			return 0, fmt.Errorf("failed to connect to peer %s: %w", addrInfo.ID, err)
		}
	}

	// Send a single ping and return its RTT.
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resCh := r.pingService.Ping(pingCtx, addrInfo.ID)
	select {
	case <-pingCtx.Done():
		return 0, fmt.Errorf("ping timeout for peer %s", addrInfo.ID)
	case res, ok := <-resCh:
		if !ok {
			return 0, fmt.Errorf("ping channel closed for peer %s", addrInfo.ID)
		}
		if res.Error != nil {
			return 0, fmt.Errorf("ping error for peer %s: %w", addrInfo.ID, res.Error)
		}
		return res.RTT, nil
	}
}

type weightedPeer struct {
	peer   peer.AddrInfo
	weight float64
}

func (r *RelayDiscovery) buildCircuitsWithWeights(peers []peer.AddrInfo, latencies map[peer.ID]time.Duration, circuitCount, hopCount int, randomnessFactor float64) []RelayInfo {
	var weightedPeers []weightedPeer
	effectiveLatencies := make(map[peer.ID]time.Duration, len(peers))
	for _, p := range peers {
		lat, ok := latencies[p.ID]
		if !ok || lat <= 0 {
			lat = defaultLatency
		}
		effectiveLatencies[p.ID] = lat
		weight := 1.0 / (float64(lat.Milliseconds()) + 1)
		weightedPeers = append(weightedPeers, weightedPeer{p, weight})
	}
	if len(weightedPeers) == 0 {
		return nil
	}

	var result []RelayInfo
	used := make(map[peer.ID]bool)

	for circuit := 0; circuit < circuitCount; circuit++ {
		for hop := 0; hop < hopCount; hop++ {
			var available []weightedPeer
			for _, wp := range weightedPeers {
				if !used[wp.peer.ID] {
					available = append(available, wp)
				}
			}
			if len(available) == 0 {
				break
			}
			selected := r.weightedSelect(available, randomnessFactor)
			if selected == nil {
				continue
			}
			result = append(result, RelayInfo{
				PeerID:    selected.peer.ID,
				AddrInfo:  selected.peer,
				Latency:   effectiveLatencies[selected.peer.ID],
				Available: latencies[selected.peer.ID] > 0,
			})
			used[selected.peer.ID] = true
		}
	}
	return result
}

func (r *RelayDiscovery) weightedSelect(peers []weightedPeer, randomnessFactor float64) *weightedPeer {
	if len(peers) == 0 {
		return nil
	}
	if len(peers) == 1 {
		return &peers[0]
	}

	adjustedWeights := make([]float64, len(peers))
	var totalWeight float64
	for i, p := range peers {
		randomWeight := r.randomFloat64() * randomnessFactor
		adjustedWeights[i] = p.weight*(1-randomnessFactor) + randomWeight
		totalWeight += adjustedWeights[i]
	}
	if totalWeight <= 0 {
		return &peers[0]
	}

	rVal := r.randomFloat64() * totalWeight
	var cumulative float64
	for i := range peers {
		cumulative += adjustedWeights[i]
		if rVal <= cumulative {
			return &peers[i]
		}
	}
	return &peers[len(peers)-1]
}

// SelectRelaysForCircuit selects a set of relays for a single circuit.
func (r *RelayDiscovery) SelectRelaysForCircuit(ctx context.Context, peers []peer.AddrInfo, hopCount int, randomnessFactor float64) ([]RelayInfo, error) {
	sampled := r.sampleFromPool(peers)
	if len(sampled) < hopCount {
		return nil, fmt.Errorf("insufficient relays")
	}
	latencies, err := r.measureLatencies(ctx, sampled)
	if err != nil {
		return nil, err
	}

	var weightedPeers []weightedPeer
	effectiveLatencies := make(map[peer.ID]time.Duration, len(sampled))
	for _, p := range sampled {
		lat, ok := latencies[p.ID]
		if !ok || lat <= 0 {
			lat = defaultLatency
		}
		effectiveLatencies[p.ID] = lat
		weight := 1.0 / float64(lat.Milliseconds()+1)
		weightedPeers = append(weightedPeers, weightedPeer{p, weight})
	}
	if len(weightedPeers) < hopCount {
		return nil, fmt.Errorf("insufficient relays")
	}

	var result []RelayInfo
	used := make(map[peer.ID]bool)

	for i := 0; i < hopCount && len(result) < hopCount; i++ {
		var available []weightedPeer
		for _, wp := range weightedPeers {
			if !used[wp.peer.ID] {
				available = append(available, wp)
			}
		}
		if len(available) == 0 {
			break
		}
		selected := r.weightedSelect(available, randomnessFactor)
		if selected != nil {
			result = append(result, RelayInfo{
				PeerID:    selected.peer.ID,
				AddrInfo:  selected.peer,
				Latency:   effectiveLatencies[selected.peer.ID],
				Available: latencies[selected.peer.ID] > 0,
			})
			used[selected.peer.ID] = true
		}
	}

	if len(result) < hopCount {
		return nil, fmt.Errorf("insufficient relays")
	}
	return result, nil
}

// FilterByExclusion filters out the specified peer IDs from the list of candidates.
func FilterByExclusion(peers []peer.AddrInfo, exclude ...peer.ID) []peer.AddrInfo {
	excludeMap := make(map[peer.ID]bool)
	for _, id := range exclude {
		excludeMap[id] = true
	}
	var result []peer.AddrInfo
	for _, p := range peers {
		if !excludeMap[p.ID] {
			result = append(result, p)
		}
	}
	return result
}

// SortByLatency sorts a slice of RelayInfo by their latency.
func SortByLatency(peers []RelayInfo) {
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].Latency < peers[j].Latency
	})
}
