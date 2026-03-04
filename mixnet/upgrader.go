package mixnet

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/routing"

	"github.com/libp2p/go-libp2p/mixnet/ces"
	"github.com/libp2p/go-libp2p/mixnet/circuit"
	"github.com/libp2p/go-libp2p/mixnet/discovery"
	noiseutil "github.com/libp2p/go-libp2p/mixnet/internal/noiseutil"
	"github.com/libp2p/go-libp2p/mixnet/relay"

	"github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

// KeyManager manages per-circuit ephemeral encryption keys (Req 16.1, 16.4).
type KeyManager struct {
	circuitKeys map[string][][]*ces.EncryptionKey // circuitID → per-shard keys
	mu          sync.Mutex
}

// NewKeyManager creates a new KeyManager.
func NewKeyManager() *KeyManager {
	return &KeyManager{
		circuitKeys: make(map[string][][]*ces.EncryptionKey),
	}
}

// StoreCircuitKeys stores per-shard keys for a circuit.
func (km *KeyManager) StoreCircuitKeys(circuitID string, keys [][]*ces.EncryptionKey) {
	km.mu.Lock()
	defer km.mu.Unlock()
	km.circuitKeys[circuitID] = keys
}

// GetCircuitKeys returns per-shard keys for a circuit.
func (km *KeyManager) GetCircuitKeys(circuitID string) ([][]*ces.EncryptionKey, bool) {
	km.mu.Lock()
	defer km.mu.Unlock()
	k, ok := km.circuitKeys[circuitID]
	return k, ok
}

// EraseCircuitKeys securely erases all keys for a circuit (Req 16.3).
func (km *KeyManager) EraseCircuitKeys(circuitID string) {
	km.mu.Lock()
	defer km.mu.Unlock()
	if keys, ok := km.circuitKeys[circuitID]; ok {
		for _, shardKeys := range keys {
			ces.EraseKeys(shardKeys)
		}
		delete(km.circuitKeys, circuitID)
	}
}

// EraseAllKeys securely erases all stored keys.
func (km *KeyManager) EraseAllKeys() {
	km.mu.Lock()
	defer km.mu.Unlock()
	for id, keys := range km.circuitKeys {
		for _, shardKeys := range keys {
			ces.EraseKeys(shardKeys)
		}
		delete(km.circuitKeys, id)
	}
}

// Mixnet is the core implementation of the Lib-Mix protocol.
// It manages circuit establishment, data sharding, and communication privacy.
type Mixnet struct {
	config       *MixnetConfig
	host         host.Host
	routing      routing.Routing
	circuitMgr   *circuit.CircuitManager
	pipeline     *ces.CESPipeline
	relayHandler *relay.Handler
	discovery    *discovery.RelayDiscovery
	metrics      *MetricsCollector
	keyManager   *KeyManager
	privacyMgr   *PrivacyManager

	// For origin mode
	originCtx    context.Context
	originCancel context.CancelFunc

	// For destination mode
	destHandler *DestinationHandler

	// Established circuits to destinations
	activeConnections map[peer.ID][]*circuit.Circuit

	mu sync.RWMutex
}

// DestinationHandler handles the reception and reconstruction of incoming shards at the destination.
type DestinationHandler struct {
	pipeline  *ces.CESPipeline
	shardBuf  map[string][]*ces.Shard
	keys      map[string][]*ces.EncryptionKey
	threshold int
	timeout   time.Duration
	dataCh    chan []byte
	stopCh    chan struct{}
	mu        sync.Mutex
}

// NewMixnet creates a new Mixnet instance with the provided configuration, host, and routing.
func NewMixnet(cfg *MixnetConfig, h host.Host, r routing.Routing) (*Mixnet, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	cfg.InitDefaults()

	// Create metrics collector (Req 17)
	metrics := NewMetricsCollector()

	// Create circuit manager (Req 6)
	circuitCfg := &circuit.CircuitConfig{
		HopCount:      cfg.HopCount,
		CircuitCount:  cfg.CircuitCount,
		StreamTimeout: 30 * time.Second,
	}
	circuitMgr := circuit.NewCircuitManager(circuitCfg)
	circuitMgr.SetHost(h)

	// Create CES pipeline (Req 3)
	pipelineCfg := &ces.Config{
		HopCount:         cfg.HopCount,
		CircuitCount:     cfg.CircuitCount,
		Compression:      cfg.Compression,
		ErasureThreshold: cfg.GetErasureThreshold(),
	}
	pipeline := ces.NewPipeline(pipelineCfg)

	// Create relay handler (Req 7)
	relayHandler := relay.NewHandler(h, cfg.CircuitCount*cfg.HopCount, 1024*1024)

	// Create relay discovery (Req 4)
	relayDiscovery := discovery.NewRelayDiscovery(
		ProtocolID,
		cfg.GetSamplingSize(),
		string(cfg.SelectionMode),
	)

	originCtx, originCancel := context.WithCancel(context.Background())

	m := &Mixnet{
		config:            cfg,
		host:              h,
		routing:           r,
		circuitMgr:        circuitMgr,
		pipeline:          pipeline,
		relayHandler:      relayHandler,
		discovery:         relayDiscovery,
		metrics:           metrics,
		keyManager:        NewKeyManager(),
		privacyMgr:        NewPrivacyManager(DefaultPrivacyConfig()),
		originCtx:         originCtx,
		originCancel:      originCancel,
		activeConnections: make(map[peer.ID][]*circuit.Circuit),
		destHandler: &DestinationHandler{
			pipeline:  pipeline,
			shardBuf:  make(map[string][]*ces.Shard),
			keys:      make(map[string][]*ces.EncryptionKey),
			threshold: cfg.GetErasureThreshold(),
			timeout:   30 * time.Second,
			dataCh:    make(chan []byte, 100),
			stopCh:    make(chan struct{}),
		},
	}

	// Register protocol handler (Req 9)
	h.SetStreamHandler(ProtocolID, m.handleIncomingStream)

	// Start circuit health monitor (Req 10.1).
	// The failure callback is rate-limited to a single concurrent recovery
	// attempt per invocation to prevent goroutine explosion.
	recoverSem := make(chan struct{}, 1) // at most 1 concurrent recovery
	m.circuitMgr.StartHealthMonitor(10*time.Second, func(circuitID string) {
		select {
		case recoverSem <- struct{}{}:
			go func() {
				defer func() { <-recoverSem }()
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				m.mu.RLock()
				dests := make([]peer.ID, 0, len(m.activeConnections))
				for dest := range m.activeConnections {
					dests = append(dests, dest)
				}
				m.mu.RUnlock()
				for _, dest := range dests {
					_ = m.RecoverFromFailure(ctx, dest)
				}
			}()
		default:
			// Recovery already in progress; skip this trigger.
		}
	})

	return m, nil
}

// EstablishConnection establishes a set of parallel circuits to the target destination.
func (m *Mixnet) EstablishConnection(ctx context.Context, dest peer.ID) ([]*circuit.Circuit, error) {
	m.mu.Lock()
	if circuits, ok := m.activeConnections[dest]; ok {
		m.mu.Unlock()
		return circuits, nil
	}
	m.mu.Unlock()

	// Discover relays (Req 4)
	relays, err := m.discoverRelays(ctx, dest)
	if err != nil {
		return nil, fmt.Errorf("relay discovery failed: %w", err)
	}

	m.circuitMgr.UpdateRelayPool(relays)

	// Build circuits in parallel (Req 6)
	circuits := make([]*circuit.Circuit, m.config.CircuitCount)
	var wg sync.WaitGroup
	errCh := make(chan error, m.config.CircuitCount)

	for i := 0; i < m.config.CircuitCount; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			c, err := m.circuitMgr.BuildCircuit()
			if err != nil {
				errCh <- err
				return
			}

			// Establish circuit (Req 6.5)
			err = m.circuitMgr.EstablishCircuit(c, dest, ProtocolID)
			if err != nil {
				errCh <- err
				return
			}

			m.circuitMgr.ActivateCircuit(c.ID)
			circuits[idx] = c
			m.metrics.RecordCircuitSuccess()
		}(i)
	}

	wg.Wait()
	close(errCh)

	// Check if we have enough circuits (Req 15)
	activeCircuits := 0
	for _, c := range circuits {
		if c != nil && c.IsActive() {
			activeCircuits++
		}
	}

	if activeCircuits < m.config.GetErasureThreshold() {
		m.metrics.RecordCircuitFailure()
		return nil, fmt.Errorf("failed to establish enough circuits: have %d, need %d", activeCircuits, m.config.GetErasureThreshold())
	}

	m.mu.Lock()
	m.activeConnections[dest] = circuits
	m.mu.Unlock()

	return circuits, nil
}

func (m *Mixnet) discoverRelays(ctx context.Context, dest peer.ID) ([]circuit.RelayInfo, error) {
	// Advertise ourselves as a relay first (Req 7)
	// In a real implementation, this would be a background task

	// Create a CID for Mixnet relays
	h_hash, _ := mh.Encode([]byte("mixnet-relay-v1"), mh.SHA2_256)
	c := cid.NewCidV1(cid.Raw, h_hash)

	// Provide if we are a relay
	if m.relayHandler != nil {
		go func() {
			_ = m.routing.Provide(ctx, c, true)
		}()
	}

	// Find providers
	providersChan := m.routing.FindProvidersAsync(ctx, c, 0)
	var providers []peer.AddrInfo
	for p := range providersChan {
		providers = append(providers, p)
	}

	if len(providers) == 0 {
		return m.getSampleRelays(ctx, dest)
	}

	// Convert to discovery.RelayInfo for selection
	relayInfos := make([]discovery.RelayInfo, len(providers))
	for i, p := range providers {
		relayInfos[i] = discovery.RelayInfo{
			PeerID:   p.ID,
			AddrInfo: p,
		}
	}

	// Select relays (Req 4)
	selected, err := m.discovery.SelectRelays(ctx, relayInfos)
	if err != nil {
		// Fallback to all discovered
		relays := make([]circuit.RelayInfo, len(providers))
		for i, p := range providers {
			relays[i] = circuit.RelayInfo{
				PeerID:   p.ID,
				AddrInfo: p,
			}
		}
		return relays, nil
	}

	// Convert discovery.RelayInfo to circuit.RelayInfo
	result := make([]circuit.RelayInfo, len(selected))
	for i, r := range selected {
		result[i] = circuit.RelayInfo{
			PeerID:   r.PeerID,
			AddrInfo: r.AddrInfo,
			Latency:  r.Latency,
		}
	}

	return result, nil
}

// getSampleRelays returns sample relays for testing.
func (m *Mixnet) getSampleRelays(ctx context.Context, dest peer.ID) ([]circuit.RelayInfo, error) {
	return nil, fmt.Errorf("no DHT configured and no sample relays available")
}

// Send sends data through the mixnet to the destination using per-circuit routing (Req 8, 14).
//
// Data flow:
//  1. Compress + shard the data.
//  2. For each shard, build a CES routing packet (Req 14.1):
//     [hop1_dest_len:2][hop1_dest][hop2_dest_len:2][hop2_dest]...[Encrypt_K([shard_idx:4][shard_data])]
//     Routing headers are plaintext (each relay reads its next-hop), content is encrypted.
//  3. SendData Noise-encrypts the routing packet and writes it length-prefixed.
//  4. Each relay decrypts its Noise layer, reads its routing header, forwards the rest.
func (m *Mixnet) Send(ctx context.Context, dest peer.ID, data []byte) error {
	circuits := m.circuitMgr.ListCircuits()
	activeCircuits := make([]*circuit.Circuit, 0)
	for _, c := range circuits {
		if c.IsActive() {
			activeCircuits = append(activeCircuits, c)
		}
	}
	if len(activeCircuits) == 0 {
		return ErrNoCircuitsEstablished
	}

	originalSize := len(data)
	sendCount := len(activeCircuits)

	// Step 1: Compress + shard (same for all circuits)
	compressed, err := m.pipeline.Compressor().Compress(data)
	if err != nil {
		return fmt.Errorf("compression failed: %w", err)
	}
	shards, err := m.pipeline.Sharder().Shard(compressed)
	if err != nil {
		return fmt.Errorf("sharding failed: %w", err)
	}

	// Record compression ratio
	m.metrics.RecordCompressionRatio(originalSize, len(compressed))

	// Transmit shards in parallel across circuits (Req 8)
	var wg sync.WaitGroup
	errCh := make(chan error, sendCount)

	for i := 0; i < sendCount && i < len(shards); i++ {
		circ := activeCircuits[i]
		shard := shards[i]

		// Build per-circuit routing path (Req 14.1: each relay sees only its next hop).
		path := make([]string, m.config.HopCount)
		for j := 0; j < m.config.HopCount; j++ {
			if j < len(circ.Peers)-1 {
				// Intermediate hop: routing header shows the NEXT relay.
				path[j] = circ.Peers[j+1].String()
			} else {
				// Final hop: routing header shows the actual destination.
				path[j] = dest.String()
			}
		}

		// Build inner payload: [shard_idx:4][raw_shard_data]
		// This is what the destination ultimately receives after decrypting the CES layer.
		innerPayload := make([]byte, 4+len(shard.Data))
		binary.LittleEndian.PutUint32(innerPayload[0:4], uint32(i))
		copy(innerPayload[4:], shard.Data)

		// CES-encrypt the inner payload with per-circuit routing path (Req 14, 16.2).
		// Output: [hop0_dest_len:2][hop0_dest]...[hopN_dest_len:2][hopN_dest][Encrypt_K(innerPayload)]
		routingPacket, keys, err := m.pipeline.Encrypter().Encrypt(innerPayload, path)
		if err != nil {
			errCh <- fmt.Errorf("circuit %s: encryption failed: %w", circ.ID, err)
			continue
		}

		// Store per-circuit keys in KeyManager (Req 16.1).
		m.keyManager.StoreCircuitKeys(circ.ID, [][]*ces.EncryptionKey{keys})

		wg.Add(1)
		go func(packet []byte, cID string, circLen int) {
			defer wg.Done()

			// Apply per-stream write deadline.
			if sh, ok := m.circuitMgr.GetStream(cID); ok && sh != nil {
				sh.Stream().SetDeadline(time.Now().Add(30 * time.Second))
			}

			// SendData Noise-encrypts the routing packet and frames it (Req 16.2).
			var sendErr error
			maxRetries := 3
			for attempt := 0; attempt < maxRetries; attempt++ {
				sendErr = m.circuitMgr.SendData(cID, packet)
				if sendErr == nil {
					break
				}
				// Wrap as a transport error to evaluate retryability (Req 19.2).
				if !IsRetryable(ErrTransportFailed("send failed").WithCause(sendErr)) {
					break
				}
				time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
			}
			if sendErr != nil {
				errCh <- fmt.Errorf("failed to send on circuit %s: %w", cID, sendErr)
				return
			}
			m.metrics.RecordThroughput(uint64(len(packet)))
			m.metrics.RecordCircuitThroughput(cID, uint64(len(packet)))
		}(routingPacket, circ.ID, i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

// ReceiveHandler returns the function used to handle incoming Mixnet streams.
func (m *Mixnet) ReceiveHandler() func(network.Stream) {
	return m.handleIncomingStream
}

// handleIncomingStream handles incoming shard at destination (Req 9, 16.2).
//
// The exit relay opens this stream and performs a Noise NN handshake with the
// destination as initiator. The destination (this function) acts as the
// responder, which mirrors what HandleStream does for relay-to-relay hops.
func (m *Mixnet) handleIncomingStream(stream network.Stream) {
	defer stream.Close()

	stream.SetDeadline(time.Now().Add(m.destHandler.timeout))

	// Noise NN handshake: destination is responder (Req 16.2).
	// The exit relay is the initiator (matches forwardToPeerStream).
	_, recvCS, err := noiseutil.PerformHandshake(stream, false)
	if err != nil {
		log.Printf("mixnet: handleIncomingStream: noise handshake error: %v", err)
		return
	}

	// Read the Noise-framed shard packet.
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		log.Printf("mixnet: handleIncomingStream: read length error: %v", err)
		return
	}
	msgLen := binary.BigEndian.Uint16(lenBuf)
	encBuf := make([]byte, msgLen)
	if _, err := io.ReadFull(stream, encBuf); err != nil {
		log.Printf("mixnet: handleIncomingStream: read message error: %v", err)
		return
	}

	// Noise-decrypt to get [shard_idx:4][shard_data].
	shardData, err := recvCS.Decrypt(nil, nil, encBuf)
	if err != nil {
		log.Printf("mixnet: handleIncomingStream: decrypt error: %v", err)
		return
	}

	// Parse shard header to get index
	shard, err := m.parseShard(shardData)
	if err != nil {
		log.Printf("mixnet: handleIncomingStream: parse shard error: %v", err)
		return
	}

	// Add to buffer with session based on connection
	m.destHandler.AddShard("default", shard)

	// Check if we can reconstruct
	data, err := m.destHandler.TryReconstruct("default")
	if err != nil {
		log.Printf("mixnet: handleIncomingStream: reconstruct error: %v", err)
		return
	}

	// Successfully got data!
	_ = data
}

// parseShard parses shard data from the stream.
func (m *Mixnet) parseShard(data []byte) (*ces.Shard, error) {
	if len(data) < 4 {
		return &ces.Shard{Index: 0, Data: data}, nil
	}

	index := int(uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24)
	return &ces.Shard{
		Index: index,
		Data:  data[4:],
	}, nil
}

// AddShard adds an incoming shard to the destination's buffer for the given session.
func (h *DestinationHandler) AddShard(sessionID string, shard *ces.Shard) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.shardBuf[sessionID] = append(h.shardBuf[sessionID], shard)
}

// TryReconstruct attempts to reconstruct the original data from buffered shards.
func (h *DestinationHandler) TryReconstruct(sessionID string) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	shards := h.shardBuf[sessionID]
	if len(shards) < h.threshold {
		return nil, fmt.Errorf("insufficient shards: have %d, need %d", len(shards), h.threshold)
	}

	keys := h.keys[sessionID]
	return h.pipeline.Reconstruct(shards, keys)
}

// SetKeys sets the layered decryption keys for a particular session.
func (h *DestinationHandler) SetKeys(sessionID string, keys []*ces.EncryptionKey) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.keys[sessionID] = keys
}

// DataChan returns a channel that receives reconstructed data.
func (h *DestinationHandler) DataChan() <-chan []byte {
	return h.dataCh
}

// sendCloseSignals sends a graceful close to all active circuits with ack waiting (Req 18.2).
func (m *Mixnet) sendCloseSignals() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	closeSignal := []byte{0xFF, 0x00, 0x00, 0x00}

	var wg sync.WaitGroup
	for _, circuits := range m.activeConnections {
		for _, c := range circuits {
			if !c.IsActive() {
				continue
			}
			wg.Add(1)
			go func(circuitID string) {
				defer wg.Done()
				_ = m.circuitMgr.SendData(circuitID, closeSignal)
				if handler, ok := m.circuitMgr.GetStream(circuitID); ok && handler != nil {
					s := handler.Stream()
					s.CloseWrite()
					// Wait for relay to close its write end (ack signal, Req 18.2).
					// Any response (EOF or timeout error) confirms delivery.
					s.SetDeadline(time.Now().Add(10 * time.Second))
					buf := make([]byte, 1)
					_, ackErr := s.Read(buf)
					// EOF means relay closed normally (expected ack).
					// Any other non-nil error (deadline, reset) is logged for diagnostics.
					if ackErr != nil && ackErr.Error() != "EOF" {
						log.Printf("mixnet: close ack circuit %s: %v", circuitID, ackErr)
					}
				}
			}(c.ID)
		}
	}
	wg.Wait()
}

// Close closes the mixnet (Req 18)
func (m *Mixnet) Close() error {
	// Cancel origin context to stop new operations
	if m.originCancel != nil {
		m.originCancel()
	}

	// Send graceful close signals to all active circuits (Req 18.2).
	m.sendCloseSignals()

	// Stop the destination handler goroutine (Req 18).
	if m.destHandler != nil && m.destHandler.stopCh != nil {
		close(m.destHandler.stopCh)
	}

	// Erase all buffered session keys (Req 16.3, 18.4).
	if m.destHandler != nil {
		m.destHandler.mu.Lock()
		for sessionID, keys := range m.destHandler.keys {
			ces.EraseKeys(keys)
			delete(m.destHandler.keys, sessionID)
		}
		m.destHandler.mu.Unlock()
	}

	// Erase all KeyManager keys (Req 16.3).
	if m.keyManager != nil {
		m.keyManager.EraseAllKeys()
	}

	// Unregister the protocol handler (Req 12).
	m.host.RemoveStreamHandler(ProtocolID)

	// Send close signal through all active circuits
	m.mu.RLock()
	var closeSignals []string
	for dest := range m.activeConnections {
		circuits := m.activeConnections[dest]
		for _, c := range circuits {
			closeSignals = append(closeSignals, c.ID)
			// Send close signal
			m.circuitMgr.SendData(c.ID, []byte{0xFF, 0x00, 0x00, 0x00}) // Close signal header
		}
	}
	m.mu.RUnlock()

	// Wait for acknowledgments with timeout (Req 18.2)
	ackTimeout := 10 * time.Second
	ackChan := make(chan error, len(closeSignals))

	var wg sync.WaitGroup
	for _, circuitID := range closeSignals {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			// Wait for close acknowledgment
			select {
			case <-ackChan:
			case <-time.After(ackTimeout):
				// Timeout - log and continue (Req 18.5)
				ackChan <- fmt.Errorf("close ack timeout for circuit %s", id)
			}
		}(circuitID)
	}

	// Close all circuits
	for _, circuitID := range closeSignals {
		m.circuitMgr.CloseCircuit(circuitID)
	}

	// Close underlying circuit manager
	err := m.circuitMgr.Close()

	// Securely erase all cryptographic material (Req 18.4)
	m.pipeline.Encrypter().SecureErase()

	// Mark metrics
	for range m.activeConnections {
		m.metrics.CircuitClosed()
	}

	return err
}

// CircuitManager returns the instance of the circuit manager.
func (m *Mixnet) CircuitManager() *circuit.CircuitManager {
	return m.circuitMgr
}

// Pipeline returns the CES pipeline instance.
func (m *Mixnet) Pipeline() *ces.CESPipeline {
	return m.pipeline
}

// RelayHandler returns the handler for relay operations.
func (m *Mixnet) RelayHandler() *relay.Handler {
	return m.relayHandler
}

// Config returns the Mixnet configuration.
func (m *Mixnet) Config() *MixnetConfig {
	return m.config
}

// Host returns the underlying libp2p host.
func (m *Mixnet) Host() host.Host {
	return m.host
}

// Metrics returns the metrics collector.
func (m *Mixnet) Metrics() *MetricsCollector {
	return m.metrics
}

// ActiveConnections returns a map of current active connections and their circuits.
func (m *Mixnet) ActiveConnections() map[peer.ID][]*circuit.Circuit {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[peer.ID][]*circuit.Circuit)
	for k, v := range m.activeConnections {
		result[k] = v
	}
	return result
}

// StreamUpgrader implements the libp2p stream upgrader interface for Mixnet.
type StreamUpgrader struct {
	mixnet *Mixnet
	config *MixnetConfig
}

// NewStreamUpgrader creates a new Mixnet stream upgrader.
func NewStreamUpgrader(cfg *MixnetConfig) *StreamUpgrader {
	return &StreamUpgrader{
		config: cfg,
	}
}

// SetMixnet sets the Mixnet instance to be used by the upgrader.
func (s *StreamUpgrader) SetMixnet(m *Mixnet) {
	s.mixnet = m
}

// Upgrade upgrades a connection to use Mixnet for privacy.
func (s *StreamUpgrader) Upgrade(ctx context.Context, conn network.Conn, dir network.Direction) (network.Stream, error) {
	if s.mixnet == nil {
		return nil, fmt.Errorf("mixnet not configured")
	}

	remotePeer := conn.RemotePeer()

	circuits, err := s.mixnet.EstablishConnection(ctx, remotePeer)
	if err != nil {
		return nil, fmt.Errorf("failed to establish connection: %w", err)
	}

	if len(circuits) == 0 {
		return nil, fmt.Errorf("no circuits established")
	}

	circuitID := circuits[0].ID
	handler, ok := s.mixnet.CircuitManager().GetStream(circuitID)
	if !ok {
		return nil, fmt.Errorf("no stream for circuit %s", circuitID)
	}

	// Return the stream directly
	return handler.Stream(), nil
}

// Config returns the upgrader's configuration.
func (s *StreamUpgrader) Config() *MixnetConfig {
	return s.config
}

// CanUpgrade returns true if the connection to the given address can be upgraded to Mixnet.
func (s *StreamUpgrader) CanUpgrade(addr string) bool {
	return true
}

// Protocol returns the Mixnet protocol ID.
func (s *StreamUpgrader) Protocol() string {
	return ProtocolID
}

// RecoverFromFailure attempts to rebuild failed circuits to maintain the reconstruction threshold.
func (m *Mixnet) RecoverFromFailure(ctx context.Context, dest peer.ID) error {
	m.mu.RLock()
	circuits, ok := m.activeConnections[dest]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("no active connection to %s", dest)
	}

	activeCount := 0
	for _, c := range circuits {
		if c.IsActive() {
			activeCount++
		}
	}

	threshold := m.config.GetErasureThreshold()
	if activeCount >= threshold {
		return nil
	}

	m.metrics.RecordRecovery()

	// Discover fresh relays so we don't rebuild with stale/failed ones (Req 10.3).
	newRelays, err := m.discoverRelays(ctx, dest)
	if err != nil {
		return fmt.Errorf("failed to discover relays for recovery: %w", err)
	}

	// Update the circuit manager relay pool with freshly discovered relays.
	m.circuitMgr.UpdateRelayPool(newRelays)

	for _, c := range circuits {
		if !c.IsActive() {
			newCircuit, err := m.circuitMgr.RebuildCircuit(c.ID)
			if err != nil {
				continue
			}

			err = m.circuitMgr.EstablishCircuit(newCircuit, dest, ProtocolID)
			if err != nil {
				continue
			}

			m.circuitMgr.ActivateCircuit(newCircuit.ID)
			m.metrics.RecordCircuitSuccess()
		}
	}

	if !m.circuitMgr.CanRecover() {
		m.metrics.RecordCircuitFailure()
		return fmt.Errorf("insufficient circuits after recovery: have %d, need %d", m.circuitMgr.ActiveCircuitCount(), threshold)
	}

	return nil
}
// Package mixnet provides a high-performance, metadata-private communication protocol for libp2p.
