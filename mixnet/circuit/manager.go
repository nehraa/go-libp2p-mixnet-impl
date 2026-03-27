// Package circuit manages the establishment and maintenance of multi-hop mixnet paths.
package circuit

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/multiformats/go-multiaddr"
)

// FailureCallback is a function type for handling circuit failures.
type FailureCallback func(circuitID string)

// RelayInfo holds metadata and performance information for a potential relay node.
type RelayInfo struct {
	PeerID    peer.ID
	AddrInfo  peer.AddrInfo
	Latency   time.Duration
	Connected bool
}

// CircuitConfig controls how many circuits are built and how long stream setup
// is allowed to take.
type CircuitConfig struct {
	HopCount     int
	CircuitCount int

	StreamTimeout time.Duration

	// AdaptiveScaling enables bounded auto-adjustment of circuit count based on
	// relay headroom and current recovery state.
	AdaptiveScalingEnabled bool
	AdaptiveScalingMin     int
	AdaptiveScalingMax     int
	AdaptiveScalingStep    int
}

// StreamHandler tracks the active libp2p stream associated with a circuit.
type StreamHandler struct {
	stream  network.Stream
	peerID  peer.ID
	writeMu sync.Mutex
}

const maxCircuitWriteChunk = 256 * 1024

// Stream returns the underlying libp2p stream bound to the circuit.
func (h *StreamHandler) Stream() network.Stream {
	return h.stream
}

// CircuitManager builds circuits, binds streams to them, and coordinates
// heartbeat-based failure handling.
type CircuitManager struct {
	cfg       *CircuitConfig
	circuits  map[string]*Circuit
	relayPool []peer.ID
	threshold int
	host      host.Host
	streams   map[string]*StreamHandler
	mu        sync.RWMutex
	wg        sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewCircuitManager creates a manager with sane defaults for recovery
// thresholds and stream setup timeouts.
func NewCircuitManager(cfg *CircuitConfig) *CircuitManager {
	threshold := cfg.CircuitCount - 1
	if threshold < 1 {
		threshold = 1
	}
	if cfg.AdaptiveScalingStep <= 0 {
		cfg.AdaptiveScalingStep = 1
	}
	if cfg.AdaptiveScalingMin <= 0 {
		cfg.AdaptiveScalingMin = cfg.CircuitCount
	}
	if cfg.AdaptiveScalingMax <= 0 {
		cfg.AdaptiveScalingMax = cfg.CircuitCount
	}
	if cfg.AdaptiveScalingMax < cfg.AdaptiveScalingMin {
		cfg.AdaptiveScalingMax = cfg.AdaptiveScalingMin
	}

	streamTimeout := cfg.StreamTimeout
	if streamTimeout == 0 {
		streamTimeout = 30 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &CircuitManager{
		cfg:       cfg,
		circuits:  make(map[string]*Circuit),
		threshold: threshold,
		streams:   make(map[string]*StreamHandler),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// SetHost installs the libp2p host used for connection and stream operations.
func (m *CircuitManager) SetHost(h host.Host) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.host = h
}

// BuildCircuits builds up to CircuitCount unique circuits from the supplied
// relay candidates while excluding the destination and local host.
func (m *CircuitManager) BuildCircuits(ctx context.Context, dest peer.ID, relays []RelayInfo) ([]*Circuit, error) {
	targetCircuits := m.AdaptiveTargetCircuitCount(len(relays))
	requiredRelays := m.cfg.HopCount * targetCircuits

	if len(relays) < requiredRelays {
		return nil, fmt.Errorf("insufficient relays: have %d, need %d",
			len(relays), requiredRelays)
	}

	filtered := m.filterRelays(relays, dest)
	if len(filtered) < requiredRelays {
		return nil, fmt.Errorf("insufficient relays after filtering: have %d, need %d",
			len(filtered), requiredRelays)
	}

	circuits := m.buildUniqueCircuits(filtered, targetCircuits)

	m.mu.Lock()
	for _, c := range circuits {
		m.circuits[c.ID] = c
	}

	m.relayPool = make([]peer.ID, len(filtered))
	for i, r := range filtered {
		m.relayPool[i] = r.PeerID
	}
	m.threshold = targetCircuits - 1
	if m.threshold < 1 {
		m.threshold = 1
	}
	m.mu.Unlock()

	return circuits, nil
}

// BuildCircuit constructs a single circuit from the manager's current relay
// pool.
func (m *CircuitManager) BuildCircuit() (*Circuit, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.relayPool) < m.cfg.HopCount {
		return nil, fmt.Errorf("insufficient relays in pool")
	}

	rand.Shuffle(len(m.relayPool), func(i, j int) {
		m.relayPool[i], m.relayPool[j] = m.relayPool[j], m.relayPool[i]
	})

	peers := make([]peer.ID, m.cfg.HopCount)
	copy(peers, m.relayPool[:m.cfg.HopCount])

	id := fmt.Sprintf("circuit-%d", len(m.circuits))
	c := NewCircuit(id, peers)
	m.circuits[id] = c
	return c, nil
}

// EstablishCircuit opens a libp2p stream to the circuit entry relay and binds
// that stream to the circuit ID.
func (m *CircuitManager) EstablishCircuit(circuit *Circuit, dest peer.ID, protocolID string) error {
	if len(circuit.Peers) == 0 {
		return fmt.Errorf("circuit has no peers")
	}

	entryPeer := circuit.Peers[0]

	m.mu.RLock()
	h := m.host
	m.mu.RUnlock()

	if h == nil {
		return fmt.Errorf("no host configured")
	}

	connectCtx, cancel := context.WithTimeout(m.ctx, m.cfg.StreamTimeout)
	defer cancel()

	var addrs []multiaddr.Multiaddr
	if m.host != nil {
		if pi := m.host.Peerstore().PeerInfo(entryPeer); len(pi.Addrs) > 0 {
			addrs = pi.Addrs
		}
	}

	if len(addrs) > 0 {
		if err := h.Connect(connectCtx, peer.AddrInfo{
			ID:    entryPeer,
			Addrs: addrs,
		}); err != nil {
			return fmt.Errorf("failed to connect to %s: %w", entryPeer, err)
		}
	}

	stream, err := h.NewStream(connectCtx, entryPeer, protocol.ID(protocolID))
	if err != nil {
		return fmt.Errorf("failed to open stream to %s: %w", entryPeer, err)
	}
	// Force multistream negotiation to flush before the first application write.
	// Without this, lazy negotiation can bundle a large shard payload into the
	// initial write and block on yamux flow control before the relay handler
	// starts consuming application data.
	if flusher, ok := stream.(interface{ Flush() error }); ok {
		if err := flusher.Flush(); err != nil {
			_ = stream.Reset()
			return fmt.Errorf("failed to negotiate stream to %s: %w", entryPeer, err)
		}
	}

	m.mu.Lock()
	m.streams[circuit.ID] = &StreamHandler{
		stream: stream,
		peerID: entryPeer,
	}
	m.mu.Unlock()

	return nil
}

// SendData writes raw bytes onto the libp2p stream associated with circuitID.
func (m *CircuitManager) SendData(circuitID string, data []byte) error {
	m.mu.RLock()
	handler, ok := m.streams[circuitID]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("no stream for circuit %s", circuitID)
	}

	return writeCircuitParts(handler, circuitID, m.cfg.StreamTimeout, data)
}

// SendDataParts writes multiple byte slices onto the libp2p stream associated
// with circuitID while holding the per-circuit write lock across the full
// sequence. This lets callers avoid building a single combined frame buffer
// while still preserving write ordering on that circuit.
func (m *CircuitManager) SendDataParts(circuitID string, parts ...[]byte) error {
	m.mu.RLock()
	handler, ok := m.streams[circuitID]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("no stream for circuit %s", circuitID)
	}

	return writeCircuitParts(handler, circuitID, m.cfg.StreamTimeout, parts...)
}

// ReadData reads raw bytes from the libp2p stream associated with circuitID.
func (m *CircuitManager) ReadData(circuitID string, buf []byte) (int, error) {
	m.mu.RLock()
	handler, ok := m.streams[circuitID]
	m.mu.RUnlock()

	if !ok {
		return 0, fmt.Errorf("no stream for circuit %s", circuitID)
	}

	return handler.stream.Read(buf)
}

func writeCircuitParts(handler *StreamHandler, circuitID string, timeout time.Duration, parts ...[]byte) error {
	handler.writeMu.Lock()
	defer handler.writeMu.Unlock()

	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return writeCircuitPartsUnlocked(handler.stream, circuitID, timeout, parts...)
}

func writeCircuitPartsUnlocked(stream network.Stream, circuitID string, timeout time.Duration, parts ...[]byte) error {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	for _, part := range parts {
		data := part
		for len(data) > 0 {
			chunk := data
			if len(chunk) > maxCircuitWriteChunk {
				chunk = chunk[:maxCircuitWriteChunk]
			}
			_ = stream.SetWriteDeadline(time.Now().Add(timeout))
			n, err := stream.Write(chunk)
			if err != nil {
				_ = stream.SetWriteDeadline(time.Time{})
				return err
			}
			if n <= 0 {
				_ = stream.SetWriteDeadline(time.Time{})
				return fmt.Errorf("short write on circuit %s", circuitID)
			}
			data = data[n:]
		}
	}
	_ = stream.SetWriteDeadline(time.Time{})
	return nil
}

// CloseCircuit closes the stream associated with circuitID and marks the
// circuit closed.
func (m *CircuitManager) CloseCircuit(circuitID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	handler, ok := m.streams[circuitID]
	if ok && handler.stream != nil {
		handler.stream.Close()
		delete(m.streams, circuitID)
	}

	if circuit, ok := m.circuits[circuitID]; ok {
		circuit.SetState(StateClosed)
	}

	return nil
}

// CloseCircuitWithContext closes the stream associated with circuitID while
// honoring ctx for cancellation or timeout.
func (m *CircuitManager) CloseCircuitWithContext(ctx context.Context, circuitID string) error {
	m.mu.Lock()
	handler, ok := m.streams[circuitID]
	if !ok {
		m.mu.Unlock()
		if circuit, ok := m.circuits[circuitID]; ok {
			circuit.SetState(StateClosed)
		}
		return nil
	}
	stream := handler.stream
	delete(m.streams, circuitID)
	m.mu.Unlock()

	if circuit, ok := m.circuits[circuitID]; ok {
		circuit.SetState(StateClosed)
	}

	if stream == nil {
		return nil
	}

	done := make(chan error, 1)
	go func() {
		done <- stream.Close()
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *CircuitManager) filterRelays(relays []RelayInfo, exclude peer.ID) []RelayInfo {
	m.mu.RLock()
	selfID := peer.ID("")
	if m.host != nil {
		selfID = m.host.ID()
	}
	m.mu.RUnlock()

	var result []RelayInfo
	for _, r := range relays {
		if r.PeerID != exclude && r.PeerID != selfID {
			result = append(result, r)
		}
	}
	return result
}

func (m *CircuitManager) buildUniqueCircuits(relays []RelayInfo, circuitCount int) []*Circuit {
	rand.Shuffle(len(relays), func(i, j int) {
		relays[i], relays[j] = relays[j], relays[i]
	})

	circuits := make([]*Circuit, 0, circuitCount)
	used := make(map[peer.ID]bool)

	for i := 0; i < circuitCount && len(circuits) < circuitCount; i++ {
		var peers []peer.ID

		for j := 0; j < m.cfg.HopCount; j++ {
			idx := i*m.cfg.HopCount + j
			if idx >= len(relays) {
				break
			}
			relayID := relays[idx].PeerID

			if !used[relayID] {
				peers = append(peers, relayID)
				used[relayID] = true
			}
		}

		if len(peers) == m.cfg.HopCount {
			circuit := NewCircuit(fmt.Sprintf("circuit-%d", i), peers)
			circuit.SetState(StateBuilding)
			circuits = append(circuits, circuit)
		}
	}

	return circuits
}

// AdaptiveTargetCircuitCount returns the bounded target circuit count based on
// the current relay pool size and manager health signals. When adaptive scaling
// is disabled, it returns the fixed configured circuit count.
func (m *CircuitManager) AdaptiveTargetCircuitCount(relayCount int) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	target := m.cfg.CircuitCount
	if !m.cfg.AdaptiveScalingEnabled {
		return target
	}
	if m.cfg.HopCount < 1 {
		return target
	}

	minCount := m.cfg.AdaptiveScalingMin
	if minCount < 1 {
		minCount = 1
	}
	maxCount := m.cfg.AdaptiveScalingMax
	if maxCount < minCount {
		maxCount = minCount
	}
	step := m.cfg.AdaptiveScalingStep
	if step < 1 {
		step = 1
	}

	if relayCount > 0 {
		maxByRelayPool := relayCount / m.cfg.HopCount
		if maxByRelayPool < 1 {
			maxByRelayPool = 1
		}
		if maxByRelayPool < maxCount {
			maxCount = maxByRelayPool
		}
	}

	active := 0
	failed := 0
	for _, c := range m.circuits {
		switch c.GetState() {
		case StateActive:
			active++
		case StateFailed, StateClosed:
			failed++
		}
	}

	recoveryCapacity := active - m.threshold
	if active < m.threshold {
		recoveryCapacity = -1
	}
	healthy := active == 0 || active >= target

	if active == 0 {
		if relayCount >= (target+step)*m.cfg.HopCount {
			target += step
		} else if relayCount < target*m.cfg.HopCount {
			target -= step
		}
	} else if relayCount >= (target+step)*m.cfg.HopCount && healthy && recoveryCapacity >= maxInt(1, target/2) {
		target += step
	} else if relayCount < target*m.cfg.HopCount || recoveryCapacity < 1 || failed > 0 && active < target {
		target -= step
	}

	if target < minCount {
		target = minCount
	}
	if target > maxCount {
		target = maxCount
	}
	if target < 1 {
		target = 1
	}
	return target
}

// EnableAdaptiveScaling enables bounded auto-scaling with conservative limits.
func (m *CircuitManager) EnableAdaptiveScaling(minCircuits, maxCircuits, step int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cfg.AdaptiveScalingEnabled = true
	m.cfg.AdaptiveScalingMin = minCircuits
	m.cfg.AdaptiveScalingMax = maxCircuits
	m.cfg.AdaptiveScalingStep = step
	if m.cfg.AdaptiveScalingStep < 1 {
		m.cfg.AdaptiveScalingStep = 1
	}
	if m.cfg.AdaptiveScalingMin < 1 {
		m.cfg.AdaptiveScalingMin = 1
	}
	if m.cfg.AdaptiveScalingMax < m.cfg.AdaptiveScalingMin {
		m.cfg.AdaptiveScalingMax = m.cfg.AdaptiveScalingMin
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ActivateCircuit marks a successfully established circuit active.
func (m *CircuitManager) ActivateCircuit(circuitID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	circuit, ok := m.circuits[circuitID]
	if !ok {
		return fmt.Errorf("circuit not found: %s", circuitID)
	}

	circuit.SetState(StateActive)
	return nil
}

// DetectFailure reports whether the circuit has failed explicitly or missed its
// heartbeat deadline.
func (m *CircuitManager) DetectFailure(circuitID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	circuit, ok := m.circuits[circuitID]
	if !ok {
		return false
	}

	state := circuit.GetState()
	if state == StateFailed || state == StateClosed {
		return true
	}

	lastHeartbeat := circuit.GetLastHeartbeat()
	if lastHeartbeat.IsZero() {
		return false
	}
	heartbeatTimeout := 30 * time.Second
	if time.Since(lastHeartbeat) > heartbeatTimeout {
		return true
	}

	return false
}

// StartHeartbeat begins periodically refreshing the circuit heartbeat timestamp
// until the manager is closed.
func (m *CircuitManager) StartHeartbeat(circuitID string, interval time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	circuit, ok := m.circuits[circuitID]
	if !ok {
		return
	}

	circuit.SetLastHeartbeat(time.Now())

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-m.ctx.Done():
				return
			case <-ticker.C:
				m.mu.Lock()
				if c, exists := m.circuits[circuitID]; exists {
					c.SetLastHeartbeat(time.Now())
				}
				m.mu.Unlock()
			}
		}
	}()
}

// ActiveCircuitCount returns the number of circuits currently in the active
// state.
func (m *CircuitManager) ActiveCircuitCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, c := range m.circuits {
		if c.IsActive() {
			count++
		}
	}
	return count
}

// CanRecover reports whether enough active circuits remain to tolerate a
// failure and continue operating.
func (m *CircuitManager) CanRecover() bool {
	return m.ActiveCircuitCount() >= m.threshold
}

// RecoveryCapacity returns how many additional circuit failures can be absorbed
// before the manager drops below its recovery threshold.
func (m *CircuitManager) RecoveryCapacity() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	active := 0
	for _, c := range m.circuits {
		if c.IsActive() {
			active++
		}
	}

	if active >= m.threshold {
		return active - m.threshold
	}
	return -1
}

// RebuildCircuit creates a replacement circuit for a failed path while trying
// to avoid reusing the failed relays.
func (m *CircuitManager) RebuildCircuit(failedID string) (*Circuit, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	failedCircuit, exists := m.circuits[failedID]
	if !exists {
		return nil, fmt.Errorf("circuit not found: %s", failedID)
	}

	state := failedCircuit.GetState()
	if state != StateFailed && state != StateClosed {
		return nil, fmt.Errorf("circuit %s is not failed", failedID)
	}

	failedPeers := make(map[peer.ID]bool)
	for _, p := range failedCircuit.Peers {
		failedPeers[p] = true
	}

	poolContains := make(map[peer.ID]struct{}, len(m.relayPool))
	for _, id := range m.relayPool {
		poolContains[id] = struct{}{}
	}

	missingFailedPeers := 0
	for _, p := range failedCircuit.Peers {
		if _, ok := poolContains[p]; !ok {
			missingFailedPeers++
		}
	}

	selected := make([]peer.ID, 0, m.cfg.HopCount)
	selectedSet := make(map[peer.ID]struct{}, m.cfg.HopCount)

	// If discovery already dropped at least one relay from the failed path, preserve
	// the surviving hops first and only replace the missing/failed ones.
	if missingFailedPeers > 0 {
		for _, p := range failedCircuit.Peers {
			if _, ok := poolContains[p]; !ok {
				continue
			}
			selected = append(selected, p)
			selectedSet[p] = struct{}{}
		}
	}

	addRelay := func(id peer.ID) bool {
		if len(selected) >= m.cfg.HopCount {
			return true
		}
		if _, ok := selectedSet[id]; ok {
			return false
		}
		selected = append(selected, id)
		selectedSet[id] = struct{}{}
		return len(selected) >= m.cfg.HopCount
	}

	relayInUse := func(id peer.ID) bool {
		for _, c := range m.circuits {
			state := c.GetState()
			if state == StateFailed || state == StateClosed {
				continue
			}
			for _, p := range c.Peers {
				if p == id {
					return true
				}
			}
		}
		return false
	}

	for _, id := range m.relayPool {
		if failedPeers[id] {
			continue
		}
		if relayInUse(id) {
			continue
		}
		if addRelay(id) {
			break
		}
	}

	// Recovery is allowed to reuse relays across different circuits as a last resort,
	// but never within the same circuit. This keeps recovery viable when discovery has
	// already pruned the dead relay and there is no fully spare path available.
	if len(selected) < m.cfg.HopCount && missingFailedPeers > 0 {
		for _, id := range m.relayPool {
			if failedPeers[id] {
				continue
			}
			if addRelay(id) {
				break
			}
		}
	}

	if len(selected) < m.cfg.HopCount {
		return nil, fmt.Errorf("insufficient available relays: have %d, need %d", len(selected), m.cfg.HopCount)
	}

	peers := selected[:m.cfg.HopCount]
	circuit := NewCircuit(fmt.Sprintf("%s-rebuilt", failedID), peers)
	circuit.SetState(StateBuilding)

	m.circuits[circuit.ID] = circuit

	return circuit, nil
}

// Close stops background work, closes all tracked streams, and marks all
// circuits closed.
func (m *CircuitManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cancel()

	for _, handler := range m.streams {
		if handler.stream != nil {
			handler.stream.Close()
		}
	}
	m.streams = make(map[string]*StreamHandler)

	for _, c := range m.circuits {
		c.SetState(StateClosed)
	}

	return nil
}

// GetCircuit returns the circuit registered under id, if present.
func (m *CircuitManager) GetCircuit(id string) (*Circuit, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	c, ok := m.circuits[id]
	return c, ok
}

// ListCircuits returns a snapshot of all circuits currently tracked by the
// manager.
func (m *CircuitManager) ListCircuits() []*Circuit {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Circuit, 0, len(m.circuits))
	for _, c := range m.circuits {
		result = append(result, c)
	}
	return result
}

// MarkCircuitFailed transitions circuitID into the failed state if it exists.
func (m *CircuitManager) MarkCircuitFailed(circuitID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if circuit, ok := m.circuits[circuitID]; ok {
		circuit.MarkFailed()
	}
}

// UpdateRelayPool replaces the manager's relay pool with the supplied relay
// candidates.
func (m *CircuitManager) UpdateRelayPool(relays []RelayInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.relayPool = make([]peer.ID, len(relays))
	for i, r := range relays {
		m.relayPool[i] = r.PeerID
	}
}

// GetRelaysForCircuit returns the ordered relay IDs used by circuitID.
func (m *CircuitManager) GetRelaysForCircuit(circuitID string) ([]peer.ID, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	circuit, ok := m.circuits[circuitID]
	if !ok {
		return nil, fmt.Errorf("circuit not found: %s", circuitID)
	}

	return circuit.Peers, nil
}

// Config returns the manager configuration.
func (m *CircuitManager) Config() *CircuitConfig {
	return m.cfg
}

// GetStream returns the stream handler registered for circuitID, if present.
func (m *CircuitManager) GetStream(circuitID string) (*StreamHandler, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	handler, ok := m.streams[circuitID]
	return handler, ok
}
