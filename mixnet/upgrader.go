package mixnet

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/core/routing"

	"github.com/libp2p/go-libp2p/mixnet/ces"
	"github.com/libp2p/go-libp2p/mixnet/circuit"
	"github.com/libp2p/go-libp2p/mixnet/discovery"
	"github.com/libp2p/go-libp2p/mixnet/relay"

	"github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

// Mixnet is the core implementation of the Lib-Mix protocol.
// It manages circuit establishment, data sharding, and communication privacy.
type Mixnet struct {
	config          *MixnetConfig
	host            host.Host
	routing         routing.Routing
	circuitMgr      *circuit.CircuitManager
	pipeline        *ces.CESPipeline
	relayHandler    *relay.Handler
	discovery       *discovery.RelayDiscovery
	metrics         *MetricsCollector
	metricsExporter *MetricsExporter
	resourceMgr     *ResourceManager
	circuitKeys     map[string][][]byte
	failureNotifier *CircuitFailureNotifier
	heartbeatStart  map[string]struct{}

	// For origin mode
	originCtx    context.Context
	originCancel context.CancelFunc

	// For destination mode
	destHandler *DestinationHandler

	// Established circuits to destinations
	activeConnections map[peer.ID][]*circuit.Circuit
	pendingShards     map[peer.ID]*PendingTransmission
	streamSessions    map[string]sessionKey
	sessionRoutes     map[string]*senderSessionRouteState
	observeDelivery   func(FinalDeliveryObservation)

	mu     sync.RWMutex
	closed atomic.Bool
}

// FinalDeliveryObservation captures what the destination-side mixnet handler
// actually received on its final inbound libp2p stream.
type FinalDeliveryObservation struct {
	Timestamp       time.Time
	NodePeer        string
	InboundPeer     string
	MessageType     string
	BaseSessionID   string
	SessionID       string
	PayloadLength   int
	WirePreviewHex  string
	WirePreviewText string
}

// PendingTransmission tracks shards that need re-scheduling after circuit recovery.
type PendingTransmission struct {
	SessionID      string
	KeyData        []byte
	Shards         []*ces.Shard
	CreatedAt      time.Time
	SessionRouting bool
}

// DestinationHandler handles the reception and reconstruction of incoming shards at the destination.
type DestinationHandler struct {
	pipeline        *ces.CESPipeline
	shardBuf        map[string]map[int]*ces.Shard
	shardTags       map[string]map[int][]byte
	totalShards     map[string]int
	timers          map[string]*time.Timer
	setupTimers     map[string]*time.Timer
	sessions        map[string]*sessionMailbox
	sessionPending  map[string]map[uint64][]byte
	sessionNextSeq  map[string]uint64
	sessionDone     map[string]time.Time
	keys            map[string]sessionKey
	keyData         map[string][]byte
	setupKeys       map[string]sessionKey
	setupKeyData    map[string][]byte
	inboundCh       chan string
	threshold       int
	timeout         time.Duration
	routeTimeout    time.Duration
	dataCh          chan []byte
	stopCh          chan struct{}
	useLengthPrefix bool
	authEnabled     bool
	authTagSize     int
	mu              sync.Mutex
}

type sessionMailbox struct {
	ch     chan []byte
	sendMu sync.Mutex
	closed bool
}

// Large stream benchmarks can deliver a high number of session fragments before
// the destination goroutine catches up. Keep enough headroom that short bursts
// do not backpressure the sender just because application reads are briefly
// behind.
const sessionChannelBuffer = 4096

const (
	msgTypeData     byte = 0x00
	msgTypeCloseReq byte = 0x01
	msgTypeCloseAck byte = 0x02
)

// maxInboundShardSize returns the upper bound on the number of bytes read from a
// single inbound stream at the destination. This prevents a malicious peer from
// forcing unbounded memory allocation before the stream deadline fires.
func maxInboundShardSize() int64 {
	return int64(relay.MaxEncryptedPayloadSize())
}

func configuredStreamTimeout(defaultTimeout time.Duration) time.Duration {
	if raw := os.Getenv("MIXNET_STREAM_TIMEOUT"); raw != "" {
		if timeout, err := time.ParseDuration(raw); err == nil && timeout > 0 {
			return timeout
		}
	}
	return defaultTimeout
}

func adaptiveCircuitScalingEnabled() bool {
	raw := strings.TrimSpace(os.Getenv("MIXNET_ADAPTIVE_CIRCUITS"))
	if raw == "" {
		return false
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

// NewMixnet creates a new Mixnet instance with the provided configuration, host, and routing.
func NewMixnet(cfg *MixnetConfig, h host.Host, r routing.Routing) (*Mixnet, error) {
	if err := cfg.Validate(); err != nil {
		return nil, ErrConfigInvalid("invalid config").WithCause(err)
	}

	cfg.InitDefaults()

	// Create metrics collector (Req 17)
	metrics := NewMetricsCollector()
	metricsExporter := NewMetricsExporter(metrics)

	// Create resource manager (Req 20).
	resourceMgr := NewLibp2pResourceManager(h, nil)

	// Create circuit manager (Req 6)
	circuitCfg := &circuit.CircuitConfig{
		HopCount:      cfg.HopCount,
		CircuitCount:  cfg.CircuitCount,
		StreamTimeout: configuredStreamTimeout(30 * time.Second),
	}
	circuitMgr := circuit.NewCircuitManager(circuitCfg)
	circuitMgr.SetHost(h)
	if adaptiveCircuitScalingEnabled() {
		minCircuits := cfg.CircuitCount - 1
		if minCircuits < 1 {
			minCircuits = 1
		}
		maxCircuits := cfg.CircuitCount + 1
		if maxCircuits > 20 {
			maxCircuits = 20
		}
		circuitMgr.EnableAdaptiveScaling(minCircuits, maxCircuits, 1)
	}

	// Create CES pipeline (Req 3)
	pipelineCfg := &ces.Config{
		HopCount:         cfg.HopCount,
		CircuitCount:     cfg.CircuitCount,
		Compression:      cfg.Compression,
		ErasureThreshold: cfg.GetErasureThreshold(),
	}
	var pipeline *ces.CESPipeline
	if cfg.UseCESPipeline {
		pipeline = ces.NewPipeline(pipelineCfg)
	}

	// Create relay handler (Req 7)
	relayHandler := relay.NewHandler(h, cfg.CircuitCount*cfg.HopCount, 1024*1024)

	// CRITICAL FIX: Register relay handler's stream handler for actual relay forwarding
	// This fixes the issue where HandleStream() was never called
	h.SetStreamHandler(relay.ProtocolID, relayHandler.HandleStream)

	// Create relay discovery (Req 4)
	relayDiscovery := discovery.NewRelayDiscoveryWithHost(
		h,
		ProtocolID,
		cfg.GetSamplingSize(),
		string(cfg.SelectionMode),
		cfg.RandomnessFactor,
	)

	originCtx, originCancel := context.WithCancel(context.Background())
	resourceMgr.StartCleanup(originCtx)

	m := &Mixnet{
		config:            cfg,
		host:              h,
		routing:           r,
		circuitMgr:        circuitMgr,
		pipeline:          pipeline,
		relayHandler:      relayHandler,
		discovery:         relayDiscovery,
		metrics:           metrics,
		metricsExporter:   metricsExporter,
		resourceMgr:       resourceMgr,
		circuitKeys:       make(map[string][][]byte),
		heartbeatStart:    make(map[string]struct{}),
		originCtx:         originCtx,
		originCancel:      originCancel,
		activeConnections: make(map[peer.ID][]*circuit.Circuit),
		pendingShards:     make(map[peer.ID]*PendingTransmission),
		streamSessions:    make(map[string]sessionKey),
		sessionRoutes:     make(map[string]*senderSessionRouteState),
		destHandler: &DestinationHandler{
			pipeline:        pipeline,
			shardBuf:        make(map[string]map[int]*ces.Shard),
			shardTags:       make(map[string]map[int][]byte),
			totalShards:     make(map[string]int),
			timers:          make(map[string]*time.Timer),
			setupTimers:     make(map[string]*time.Timer),
			sessions:        make(map[string]*sessionMailbox),
			sessionPending:  make(map[string]map[uint64][]byte),
			sessionNextSeq:  make(map[string]uint64),
			sessionDone:     make(map[string]time.Time),
			keys:            make(map[string]sessionKey),
			keyData:         make(map[string][]byte),
			setupKeys:       make(map[string]sessionKey),
			setupKeyData:    make(map[string][]byte),
			inboundCh:       make(chan string, 100),
			threshold:       cfg.GetErasureThreshold(),
			timeout:         30 * time.Second,
			routeTimeout:    cfg.SessionRouteIdleTimeout,
			dataCh:          make(chan []byte, 100),
			stopCh:          make(chan struct{}),
			useLengthPrefix: cfg.PayloadPaddingStrategy != PaddingStrategyNone,
			authEnabled:     cfg.EnableAuthTag,
			authTagSize:     cfg.AuthTagSize,
		},
	}

	// Wire relay resource/backpressure hooks (Req 20.4, 20.5).
	relayHandler.SetSessionRouteIdleTimeout(cfg.SessionRouteIdleTimeout)
	relayHandler.SetBandwidthBackpressure(func(ctx context.Context, bytes int64) error {
		return resourceMgr.WaitForBandwidth(ctx, bytes)
	})
	relayHandler.SetBandwidthRecorder(func(direction string, bytes int64) {
		resourceMgr.RecordBandwidth(bytes, direction)
		m.metrics.RecordRelayResourceUsage(resourceMgr.ActiveCircuitCount(), resourceMgr.BandwidthPerSec())
		m.metrics.RecordResourceUtilization(resourceMgr.UtilizationPercent())
	})
	relayHandler.SetUtilizationReporter(func(activeCircuits int) {
		resourceMgr.SetActiveCircuitCount(activeCircuits)
		m.metrics.RecordRelayResourceUsage(activeCircuits, resourceMgr.BandwidthPerSec())
		m.metrics.RecordResourceUtilization(resourceMgr.UtilizationPercent())
	})

	// Register protocol handler (Req 9)
	h.SetStreamHandler(ProtocolID, m.handleIncomingStream)
	h.SetStreamHandler(KeyExchangeProtocolID, relayHandler.HandleKeyExchange)

	// Start active failure detection (Req 10.1-10.4).
	m.failureNotifier = NewCircuitFailureNotifier(m, h)
	if err := m.failureNotifier.Start(originCtx); err != nil {
		return nil, ErrCircuitFailed("failed to start failure notifier").WithCause(err)
	}

	if addr := os.Getenv("LIBP2P_MIXNET_METRICS_ADDR"); addr != "" {
		go func() {
			if err := m.StartMetricsEndpoint(addr); err != nil {
				log.Printf("[mixnet] metrics endpoint failed: %v", err)
			}
		}()
	}

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

	// Req 11/16: use transport capability detection if address data is available.
	if info, err := DetectTransportCapabilities(m.host, dest); err == nil && len(info.Multiaddrs) > 0 {
		if !SupportsStandardTransport(info) {
			return nil, ErrTransportFailed(fmt.Sprintf("destination %s does not advertise tcp/quic/webrtc transport", dest))
		}
	}

	// Req 12.3: reject destination peers that do not advertise the mixnet ProtocolID.
	supported, err := VerifyProtocolSupport(m.host, dest, protocol.ID(ProtocolID))
	if err != nil || !supported {
		// Peerstore protocol lists can be stale/empty until we connect and identify.
		pi := m.host.Peerstore().PeerInfo(dest)
		if len(pi.Addrs) > 0 {
			connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_ = m.host.Connect(connectCtx, peer.AddrInfo{ID: dest, Addrs: pi.Addrs})
			cancel()
		}
		supported, err = VerifyProtocolSupport(m.host, dest, protocol.ID(ProtocolID))
		if err != nil {
			return nil, ErrProtocolError(fmt.Sprintf("failed to verify destination protocol support for %s", dest)).WithCause(err)
		}
		if !supported {
			return nil, ErrProtocolError(fmt.Sprintf("destination %s does not advertise protocol %s", dest, ProtocolID))
		}
	}

	// Discover relays (Req 4)
	relays, err := m.discoverRelays(ctx, dest)
	if err != nil {
		return nil, ErrDiscoveryFailed("relay discovery failed").WithCause(err)
	}

	// Build circuits with unique relay sets (Req 6.2).
	built, err := m.circuitMgr.BuildCircuits(ctx, dest, relays)
	if err != nil {
		return nil, ErrCircuitFailed("failed to build circuits").WithCause(err)
	}
	if len(built) != m.config.CircuitCount {
		return nil, ErrCircuitFailed(fmt.Sprintf("failed to build required circuits: have %d, need %d", len(built), m.config.CircuitCount))
	}

	// Establish circuits in parallel (Req 6.3-6.5).
	circuits := make([]*circuit.Circuit, len(built))
	copy(circuits, built)
	var wg sync.WaitGroup
	errCh := make(chan error, len(circuits))

	for i := 0; i < len(circuits); i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Establish circuit to entry relay (Req 6.3-6.5).
			err := m.circuitMgr.EstablishCircuit(circuits[idx], dest, relay.ProtocolID)
			if err != nil {
				errCh <- ErrCircuitFailed("failed to establish circuit").WithCause(err)
				return
			}

			m.circuitMgr.ActivateCircuit(circuits[idx].ID)
			m.metrics.RecordCircuitSuccess()
		}(i)
	}

	wg.Wait()
	close(errCh)

	var establishErr error
	for err := range errCh {
		if err != nil {
			establishErr = err
			break
		}
	}

	// Req 6.6: if any circuit establishment fails, tear down all circuits.
	if establishErr != nil {
		for _, c := range circuits {
			if c == nil {
				continue
			}
			_ = m.circuitMgr.CloseCircuit(c.ID)
		}
		m.metrics.RecordCircuitFailure()
		return nil, ErrCircuitFailed("failed to establish circuits").WithCause(establishErr)
	}

	// Check if we have enough circuits (Req 15)
	activeCircuits := 0
	for _, c := range circuits {
		if c != nil && c.IsActive() {
			activeCircuits++
		}
	}

	if activeCircuits < m.config.GetErasureThreshold() {
		for _, c := range circuits {
			if c == nil {
				continue
			}
			_ = m.circuitMgr.CloseCircuit(c.ID)
		}
		m.metrics.RecordCircuitFailure()
		return nil, ErrCircuitFailed(fmt.Sprintf("failed to establish enough circuits: have %d, need %d", activeCircuits, m.config.GetErasureThreshold()))
	}

	m.mu.Lock()
	m.activeConnections[dest] = circuits
	m.mu.Unlock()

	// Prevent config mutation while circuits are active (Req 15.5).
	m.config.Lock()
	m.StartHeartbeatMonitoring(defaultHeartbeatInterval)

	return circuits, nil
}

func (m *Mixnet) discoverRelays(ctx context.Context, dest peer.ID) ([]circuit.RelayInfo, error) {
	if m.routing == nil {
		return nil, ErrDiscoveryFailed("routing not configured")
	}

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

	// CRITICAL FIX (Req 12): Verify protocol support using Peerstore
	// After getting providers, verify each peer actually advertises /lib-mix/1.0.0
	var validRelays []peer.AddrInfo
	for _, p := range providers {
		supported, err := m.host.Peerstore().SupportsProtocols(p.ID, protocol.ID(ProtocolID))
		if err == nil && len(supported) > 0 {
			validRelays = append(validRelays, p)
		}
	}

	// Use only verified relays
	providers = validRelays

	if len(providers) == 0 {
		return m.getSampleRelays(ctx, dest)
	}

	// AC 4.4: filter out origin and destination peers
	providers = discovery.FilterByExclusion(providers, dest, m.host.ID())

	// AC 4.2: DHT pool must be at least 3x required relay count
	required := m.config.HopCount * m.config.CircuitCount
	if len(providers) < required*3 {
		return nil, ErrDiscoveryFailed(fmt.Sprintf("insufficient relay pool: have %d, need %d", len(providers), required*3))
	}

	// Select relays using configured mode and RTT measurements (Req 4, 5)
	selected, err := m.discovery.FindRelays(ctx, providers, m.config.HopCount, m.config.CircuitCount)
	if err != nil {
		return nil, ErrDiscoveryFailed("relay selection failed").WithCause(err)
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
	return nil, ErrDiscoveryFailed("no DHT configured and no sample relays available")
}

// Send transmits data to the specified destination through the mixnet.
func (m *Mixnet) Send(ctx context.Context, dest peer.ID, data []byte) error {
	sessionID := fmt.Sprintf("%s-%d", dest.String(), time.Now().UnixNano())
	return m.SendWithSession(ctx, dest, data, sessionID)
}

// SendWithSession sends data using a caller-provided session ID (used by MixnetStream).
func (m *Mixnet) SendWithSession(ctx context.Context, dest peer.ID, data []byte, sessionID string) error {
	sessionID = normalizeSessionID(sessionID)
	circuits := m.activeCircuitsForDest(dest)
	if len(circuits) == 0 {
		var err error
		circuits, err = m.EstablishConnection(ctx, dest)
		if err != nil {
			return err
		}
		circuits = activeCircuitSubset(circuits)
	}
	if len(circuits) == 0 {
		return ErrCircuitFailed(fmt.Sprintf("no active circuits to %s", dest))
	}
	if sessionRoutingEnabled(m.config) {
		return m.sendWithSessionRouted(ctx, dest, data, sessionID, circuits)
	}

	var (
		keyData    []byte
		shards     []*ces.Shard
		streamKey  sessionKey
		haveStream bool
	)
	streamKey, haveStream = m.streamSession(sessionID)
	if m.config.UseCESPipeline {
		// Record original size for compression metrics
		originalSize := len(data)

		// Process through CES pipeline: compress first.
		compressed, err := m.pipeline.Compressor().Compress(data)
		if err != nil {
			return ErrCompressionFailed("compression failed").WithCause(err)
		}

		payload := compressed
		useLengthPrefix := m.config.PayloadPaddingStrategy != PaddingStrategyNone
		if useLengthPrefix {
			origLen := len(payload)
			padded, _, err := applyPayloadPadding(payload, m.config)
			if err != nil {
				return ErrCompressionFailed("padding failed").WithCause(err)
			}
			payload = addLengthPrefixWithLen(padded, origLen)
		}

		// Encrypt before sharding (Req 3.3).
		var encryptedPayload []byte
		var keyDataOut []byte
		if haveStream {
			encryptedPayload, err = encryptSessionPayloadWithKey(payload, streamKey, sessionID)
			if err == nil {
				keyDataOut = encodeSessionKeyData(streamKey)
			}
		} else {
			encryptedPayload, keyDataOut, err = encryptSessionPayload(payload)
		}
		if err != nil {
			return ErrEncryptionFailed("session encryption failed").WithCause(err)
		}

		shardsOut, err := m.pipeline.Sharder().Shard(encryptedPayload)
		if err != nil {
			return ErrShardingFailed("sharding failed").WithCause(err)
		}

		// Record compression ratio
		m.metrics.RecordCompressionRatio(originalSize, len(compressed))
		keyData = keyDataOut
		shards = shardsOut
	} else {
		payload := data
		useLengthPrefix := m.config.PayloadPaddingStrategy != PaddingStrategyNone
		if useLengthPrefix {
			origLen := len(payload)
			padded, _, err := applyPayloadPadding(payload, m.config)
			if err != nil {
				return ErrCompressionFailed("padding failed").WithCause(err)
			}
			payload = addLengthPrefixWithLen(padded, origLen)
		}
		var (
			keyDataOut []byte
			shardsOut  []*ces.Shard
			err        error
		)
		if m.config.UseCSE {
			if haveStream {
				shardsOut, err = encryptSessionShardsWithKey(payload, streamKey, len(circuits), sessionID)
				if err == nil {
					keyDataOut = encodeSessionKeyData(streamKey)
				}
			} else {
				shardsOut, keyDataOut, err = encryptSessionShards(payload, len(circuits))
			}
		} else {
			var encryptedPayload []byte
			if haveStream {
				encryptedPayload, err = encryptSessionPayloadWithKey(payload, streamKey, sessionID)
				if err == nil {
					keyDataOut = encodeSessionKeyData(streamKey)
				}
			} else {
				encryptedPayload, keyDataOut, err = encryptSessionPayload(payload)
			}
			if err == nil {
				shardsOut, err = shardEvenly(encryptedPayload, len(circuits))
			}
		}
		if err != nil {
			return ErrEncryptionFailed("session encryption failed").WithCause(err)
		}
		keyData = keyDataOut
		shards = shardsOut
	}

	sessionIDBytes := []byte(sessionID)

	// Ensure hop keys are established for all circuits.
	if err := m.ensureCircuitKeys(ctx, circuits); err != nil {
		return ErrEncryptionFailed("failed to establish hop keys").WithCause(err)
	}

	var authKey *sessionKey
	if m.config.EnableAuthTag {
		if haveStream {
			authKey = &streamKey
		} else {
			decoded, err := decodeSessionKeyData(keyData)
			if err != nil {
				return ErrEncryptionFailed("auth key decode failed").WithCause(err)
			}
			authKey = &decoded
		}
	}

	// Enforce 1:1 shard-to-circuit mapping (Req 2.4, 8.1).
	if len(shards) != len(circuits) {
		return ErrShardingFailed(fmt.Sprintf("shard count mismatch: have %d shards, %d circuits", len(shards), len(circuits)))
	}
	m.setPendingTransmission(dest, sessionID, keyData, shards, false)
	if err := m.sendShardsAcrossCircuits(ctx, dest, sessionIDBytes, keyData, shards, circuits, authKey); err != nil {
		if ctx.Err() != nil || !IsRetryable(err) {
			return err
		}
		if recoverErr := m.RecoverFromFailure(ctx, dest); recoverErr != nil {
			return ErrCircuitFailed("failed to recover after send failure").WithCause(errors.Join(err, recoverErr))
		}
		return nil
	}
	m.clearPendingTransmission(dest, sessionID)
	return nil
}

func (m *Mixnet) sendWithSessionRouted(ctx context.Context, dest peer.ID, data []byte, sessionID string, circuits []*circuit.Circuit) error {
	baseID, seq, hasSeq := parseStreamWriteSequence(sessionID)
	if !hasSeq {
		baseID = sessionID
		seq = m.nextRouteSequence(baseID)
		hasSeq = true
		sessionID = routedSessionID(baseID, hasSeq, seq)
	}
	streamKey, _, err := m.ensureStreamSession(baseID)
	if err != nil {
		return ErrEncryptionFailed("session setup failed").WithCause(err)
	}
	m.touchRouteSessionState(baseID)

	var (
		keyData = encodeSessionKeyData(streamKey)
		shards  []*ces.Shard
	)

	if m.config.UseCESPipeline {
		originalSize := len(data)
		compressed, err := m.pipeline.Compressor().Compress(data)
		if err != nil {
			return ErrCompressionFailed("compression failed").WithCause(err)
		}
		payload := compressed
		if m.config.PayloadPaddingStrategy != PaddingStrategyNone {
			origLen := len(payload)
			padded, _, err := applyPayloadPadding(payload, m.config)
			if err != nil {
				return ErrCompressionFailed("padding failed").WithCause(err)
			}
			payload = addLengthPrefixWithLen(padded, origLen)
		}
		encryptedPayload, err := encryptSessionPayloadWithKey(payload, streamKey, sessionID)
		if err != nil {
			return ErrEncryptionFailed("session encryption failed").WithCause(err)
		}
		shards, err = m.pipeline.Sharder().Shard(encryptedPayload)
		if err != nil {
			return ErrShardingFailed("sharding failed").WithCause(err)
		}
		m.metrics.RecordCompressionRatio(originalSize, len(compressed))
	} else {
		payload := data
		if m.config.PayloadPaddingStrategy != PaddingStrategyNone {
			origLen := len(payload)
			padded, _, err := applyPayloadPadding(payload, m.config)
			if err != nil {
				return ErrCompressionFailed("padding failed").WithCause(err)
			}
			payload = addLengthPrefixWithLen(padded, origLen)
		}
		if m.config.UseCSE {
			shards, err = encryptSessionShardsWithKey(payload, streamKey, len(circuits), sessionID)
		} else {
			encryptedPayload, encErr := encryptSessionPayloadWithKey(payload, streamKey, sessionID)
			if encErr != nil {
				err = encErr
			} else {
				shards, err = shardEvenly(encryptedPayload, len(circuits))
			}
		}
		if err != nil {
			return ErrEncryptionFailed("session encryption failed").WithCause(err)
		}
	}

	if len(shards) != len(circuits) {
		return ErrShardingFailed(fmt.Sprintf("shard count mismatch: have %d shards, %d circuits", len(shards), len(circuits)))
	}
	if err := m.ensureCircuitKeys(ctx, circuits); err != nil {
		return ErrEncryptionFailed("failed to establish hop keys").WithCause(err)
	}

	var authKey *sessionKey
	if m.config.EnableAuthTag {
		authKey = &streamKey
	}

	m.setPendingTransmission(dest, sessionID, keyData, shards, true)
	if err := m.sendSessionSetupAcrossCircuits(ctx, dest, baseID, keyData, circuits); err != nil {
		if ctx.Err() != nil || !IsRetryable(err) {
			return err
		}
		m.resetRouteSetup(baseID)
		if recoverErr := m.RecoverFromFailure(ctx, dest); recoverErr != nil {
			return ErrCircuitFailed("failed to recover after setup failure").WithCause(errors.Join(err, recoverErr))
		}
		return nil
	}
	if err := m.sendSessionDataAcrossCircuits(ctx, dest, baseID, hasSeq, seq, sessionID, keyData, shards, circuits, authKey); err != nil {
		if ctx.Err() != nil || !IsRetryable(err) {
			return err
		}
		m.resetRouteSetup(baseID)
		if recoverErr := m.RecoverFromFailure(ctx, dest); recoverErr != nil {
			return ErrCircuitFailed("failed to recover after send failure").WithCause(errors.Join(err, recoverErr))
		}
		return nil
	}
	m.clearPendingTransmission(dest, sessionID)
	return nil
}

func (m *Mixnet) sendSessionSetupAcrossCircuits(ctx context.Context, dest peer.ID, baseID string, keyData []byte, circuits []*circuit.Circuit) error {
	mode := sessionRouteModeForConfig(m.config)
	setupData, err := encodeSessionSetupDeliveryPayload(baseID, keyData)
	if err != nil {
		return ErrProtocolError("failed to encode session setup").WithCause(err)
	}
	for idx, c := range circuits {
		circuitID := c.ID
		if m.routeSetupComplete(baseID, circuitID) {
			continue
		}
		keyID := m.circuitKeyID(c)
		hopKeys, ok := m.getCircuitKeys(keyID)
		if !ok {
			return ErrEncryptionFailed(fmt.Sprintf("missing hop keys for circuit %s", circuitID))
		}
		onionHeader, err := encryptOnionHeader(setupData, circuits[idx], dest, hopKeys)
		if err != nil {
			return ErrEncryptionFailed(fmt.Sprintf("failed to encrypt session setup for circuit %s", circuitID)).WithCause(err)
		}
		framePayload, err := encodeSessionSetupFramePayload(baseID, mode, onionHeader, keyData)
		if err != nil {
			return ErrProtocolError("failed to frame session setup").WithCause(err)
		}
		frameHeader, err := buildEncryptedFrameHeader(keyID, sessionSetupFrameVersion(mode), len(framePayload))
		if err != nil {
			return ErrProtocolError("failed to build session setup header").WithCause(err)
		}
		if err := m.circuitMgr.SendDataParts(circuitID, frameHeader, framePayload); err != nil {
			return ErrTransportFailed(fmt.Sprintf("failed to send setup on circuit %s", circuitID)).WithCause(err)
		}
		m.markRouteSetup(baseID, circuitID)
	}
	return nil
}

func (m *Mixnet) sendSessionDataAcrossCircuits(ctx context.Context, dest peer.ID, baseID string, hasSeq bool, seq uint64, sessionID string, keyData []byte, shards []*ces.Shard, circuits []*circuit.Circuit, authKey *sessionKey) error {
	mode := sessionRouteModeForConfig(m.config)
	resultCh := make(chan shardSendResult, len(shards))
	for i, shard := range shards {
		circuitID := circuits[i].ID
		go func(idx int, sh *ces.Shard, circuitID string) {
			var authTag []byte
			if m.config.EnableAuthTag && authKey != nil {
				authTag = computeAuthTag(*authKey, []byte(sessionID), uint32(sh.Index), uint32(len(shards)), sh.Data, false, nil, m.config.AuthTagSize)
			}
			err := m.sendSessionDataFrameOnCircuit(baseID, hasSeq, seq, sh, len(shards), circuits[idx], authTag, mode)
			if err != nil {
				m.clearRouteSetupCircuit(baseID, circuitID)
				if setupErr := m.sendSessionSetupAcrossCircuits(ctx, dest, baseID, keyData, []*circuit.Circuit{circuits[idx]}); setupErr == nil {
					err = m.sendSessionDataFrameOnCircuit(baseID, hasSeq, seq, sh, len(shards), circuits[idx], authTag, mode)
				}
			}
			if err != nil {
				resultCh <- shardSendResult{circuitID: circuitID, err: ErrTransportFailed(fmt.Sprintf("failed to send data on circuit %s", circuitID)).WithCause(err)}
				return
			}
			resultCh <- shardSendResult{circuitID: circuitID}
		}(i, shard, circuitID)
	}
	for i := 0; i < len(shards); i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case result := <-resultCh:
			if result.err != nil {
				m.clearRouteSetup(baseID)
				return result.err
			}
		}
	}
	return nil
}

func (m *Mixnet) sendSessionDataFrameOnCircuit(baseID string, hasSeq bool, seq uint64, shard *ces.Shard, totalShards int, c *circuit.Circuit, authTag []byte, mode sessionRouteMode) error {
	framePayload, err := encodeSessionDataFramePayload(baseID, hasSeq, seq, shard, totalShards, authTag)
	if err != nil {
		return ErrProtocolError("failed to encode session data").WithCause(err)
	}
	keyID := m.circuitKeyID(c)
	frameHeader, err := buildEncryptedFrameHeader(keyID, sessionDataFrameVersion(mode), len(framePayload))
	if err != nil {
		return ErrProtocolError("failed to build session data header").WithCause(err)
	}
	if err := m.circuitMgr.SendDataParts(c.ID, frameHeader, framePayload); err != nil {
		return err
	}
	m.metrics.RecordThroughput(uint64(len(frameHeader) + len(framePayload)))
	return nil
}

func normalizeSessionID(sessionID string) string {
	if len(sessionID) <= 64 {
		return sessionID
	}
	sum := sha256.Sum256([]byte(sessionID))
	return hex.EncodeToString(sum[:])
}

func (m *Mixnet) registerStreamSession(sessionID string) error {
	baseID := baseSessionID(normalizeSessionID(sessionID))
	mode := sessionCryptoModeWholeStream
	if m.config != nil && m.config.UseCSE {
		mode = sessionCryptoModePerShardStream
	}
	key, err := newSessionKey(mode)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.streamSessions == nil {
		m.streamSessions = make(map[string]sessionKey)
	}
	m.streamSessions[baseID] = key
	return nil
}

func (m *Mixnet) ensureStreamSession(sessionID string) (sessionKey, bool, error) {
	baseID := baseSessionID(normalizeSessionID(sessionID))
	if key, ok := m.streamSession(baseID); ok {
		return key, true, nil
	}
	mode := sessionCryptoModeWholeStream
	if m.config != nil && m.config.UseCSE {
		mode = sessionCryptoModePerShardStream
	}
	key, err := newSessionKey(mode)
	if err != nil {
		return sessionKey{}, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.streamSessions == nil {
		m.streamSessions = make(map[string]sessionKey)
	}
	if existing, ok := m.streamSessions[baseID]; ok {
		return existing, true, nil
	}
	m.streamSessions[baseID] = key
	return key, false, nil
}

func (m *Mixnet) streamSession(sessionID string) (sessionKey, bool) {
	baseID := baseSessionID(normalizeSessionID(sessionID))
	m.mu.RLock()
	defer m.mu.RUnlock()
	key, ok := m.streamSessions[baseID]
	return key, ok
}

func (m *Mixnet) touchRouteSessionState(baseID string) *senderSessionRouteState {
	timeout := 30 * time.Second
	if m.config != nil && m.config.SessionRouteIdleTimeout > 0 {
		timeout = m.config.SessionRouteIdleTimeout
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sessionRoutes == nil {
		m.sessionRoutes = make(map[string]*senderSessionRouteState)
	}
	state, ok := m.sessionRoutes[baseID]
	if !ok {
		state = &senderSessionRouteState{
			setupByCircuit: make(map[string]struct{}),
		}
		m.sessionRoutes[baseID] = state
	}
	state.lastUsed = time.Now()
	if state.timer == nil {
		state.timer = time.AfterFunc(timeout, func() {
			m.clearStreamSession(baseID)
		})
	} else {
		state.timer.Reset(timeout)
	}
	return state
}

func (m *Mixnet) nextRouteSequence(baseID string) uint64 {
	timeout := 30 * time.Second
	if m.config != nil && m.config.SessionRouteIdleTimeout > 0 {
		timeout = m.config.SessionRouteIdleTimeout
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sessionRoutes == nil {
		m.sessionRoutes = make(map[string]*senderSessionRouteState)
	}
	state := m.sessionRoutes[baseID]
	if state == nil {
		state = &senderSessionRouteState{
			setupByCircuit: make(map[string]struct{}),
		}
		m.sessionRoutes[baseID] = state
	}
	state.lastUsed = time.Now()
	if state.timer == nil {
		state.timer = time.AfterFunc(timeout, func() {
			m.clearStreamSession(baseID)
		})
	} else {
		state.timer.Reset(timeout)
	}
	seq := state.nextSeq
	state.nextSeq++
	return seq
}

func (m *Mixnet) routeSetupComplete(baseID, circuitID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	state := m.sessionRoutes[baseID]
	if state == nil {
		return false
	}
	_, ok := state.setupByCircuit[circuitID]
	return ok
}

func (m *Mixnet) markRouteSetup(baseID, circuitID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sessionRoutes == nil {
		m.sessionRoutes = make(map[string]*senderSessionRouteState)
	}
	state := m.sessionRoutes[baseID]
	if state == nil {
		state = &senderSessionRouteState{
			setupByCircuit: make(map[string]struct{}),
		}
		m.sessionRoutes[baseID] = state
	}
	if state.setupByCircuit == nil {
		state.setupByCircuit = make(map[string]struct{})
	}
	state.setupByCircuit[circuitID] = struct{}{}
}

func (m *Mixnet) clearRouteSetup(baseID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if state := m.sessionRoutes[baseID]; state != nil {
		if state.timer != nil {
			state.timer.Stop()
		}
		delete(m.sessionRoutes, baseID)
	}
}

func (m *Mixnet) resetRouteSetup(baseID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.sessionRoutes[baseID]
	if state == nil {
		return
	}
	state.setupByCircuit = make(map[string]struct{})
}

func (m *Mixnet) clearRouteSetupCircuit(baseID, circuitID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.sessionRoutes[baseID]
	if state == nil || state.setupByCircuit == nil {
		return
	}
	delete(state.setupByCircuit, circuitID)
}

func (m *Mixnet) clearStreamSession(sessionID string) {
	baseID := baseSessionID(normalizeSessionID(sessionID))
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.streamSessions == nil {
		return
	}
	if key, ok := m.streamSessions[baseID]; ok {
		ces.SecureEraseBytes(key.Key)
		ces.SecureEraseBytes(key.Nonce)
		delete(m.streamSessions, baseID)
	}
	if state := m.sessionRoutes[baseID]; state != nil {
		if state.timer != nil {
			state.timer.Stop()
		}
		delete(m.sessionRoutes, baseID)
	}
}

func (m *Mixnet) closeSessionRouting(ctx context.Context, dest peer.ID, sessionID string) error {
	if m == nil || !sessionRoutingEnabled(m.config) {
		return nil
	}
	baseID := baseSessionID(normalizeSessionID(sessionID))
	circuits := m.activeCircuitsForDest(dest)
	if len(circuits) == 0 {
		m.clearRouteSetup(baseID)
		return nil
	}
	payload, err := encodeSessionCloseFramePayload(baseID)
	if err != nil {
		return err
	}
	var firstErr error
	for _, c := range circuits {
		if c == nil || !m.routeSetupComplete(baseID, c.ID) {
			continue
		}
		keyID := m.circuitKeyID(c)
		frameHeader, err := buildEncryptedFrameHeader(keyID, frameVersionSessionClose, len(payload))
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := m.circuitMgr.SendDataParts(c.ID, frameHeader, payload); err != nil && firstErr == nil && ctx != nil && ctx.Err() == nil {
			firstErr = err
		}
	}
	m.clearRouteSetup(baseID)
	return firstErr
}

func (m *Mixnet) headerPaddingConfig() *PrivacyPaddingConfig {
	if m == nil || m.config == nil || !m.config.HeaderPaddingEnabled {
		return nil
	}
	return &PrivacyPaddingConfig{
		Enabled:  true,
		MinBytes: m.config.HeaderPaddingMin,
		MaxBytes: m.config.HeaderPaddingMax,
	}
}

func shardEvenly(data []byte, total int) ([]*ces.Shard, error) {
	if total <= 0 {
		return nil, fmt.Errorf("invalid shard count: %d", total)
	}
	parts := make([]*ces.Shard, total)
	base := len(data) / total
	remainder := len(data) % total
	offset := 0
	for i := 0; i < total; i++ {
		size := base
		if i < remainder {
			size++
		}
		end := offset + size
		if end > len(data) {
			end = len(data)
		}
		// Expose immutable views into the source buffer instead of cloning each
		// segment. This keeps header-only and full-onion sender paths from paying
		// an extra full-payload copy before the shard ever hits the wire.
		parts[i] = &ces.Shard{Index: i, Data: data[offset:end]}
		offset = end
	}
	return parts, nil
}

// ReceiveHandler returns the function used to handle incoming Mixnet streams.
func (m *Mixnet) ReceiveHandler() func(network.Stream) {
	return m.handleIncomingStream
}

// handleIncomingStream handles incoming shard at destination (Req 9)
func (m *Mixnet) handleIncomingStream(stream network.Stream) {
	defer stream.Close()

	// Read the shard data with timeout, bounded to maxInboundShardSize to
	// prevent a peer from causing unbounded memory allocation.
	stream.SetDeadline(time.Now().Add(m.destHandler.timeout))

	inboundLimit := maxInboundShardSize()
	shardData, err := io.ReadAll(io.LimitReader(stream, inboundLimit+1))
	if err != nil || len(shardData) == 0 {
		if err != nil && os.Getenv("LIBP2P_MIXNET_BENCH_DEBUG") != "" {
			log.Printf("[mixnet bench host=%s] inbound read failed: %v", m.host.ID(), err)
		}
		return
	}

	// Reject frames that hit or exceed the size cap.
	if int64(len(shardData)) > inboundLimit {
		if os.Getenv("LIBP2P_MIXNET_BENCH_DEBUG") != "" {
			log.Printf("[mixnet bench host=%s] inbound shard too large: got=%d limit=%d", m.host.ID(), len(shardData), inboundLimit)
		}
		return
	}
	if len(shardData) < 1 {
		return
	}
	baseObs := FinalDeliveryObservation{
		Timestamp:       time.Now(),
		NodePeer:        m.host.ID().String(),
		InboundPeer:     stream.Conn().RemotePeer().String(),
		PayloadLength:   len(shardData),
		WirePreviewHex:  previewHexBytes(shardData),
		WirePreviewText: previewTextBytes(shardData),
	}
	switch shardData[0] {
	case msgTypeCloseReq:
		baseObs.MessageType = "close-request"
		m.recordFinalDeliveryObservation(baseObs)
		_, _ = stream.Write([]byte{msgTypeCloseAck})
		return
	case msgTypeData:
		baseObs.MessageType = "data"
		m.recordFinalDeliveryObservation(baseObs)
		// continue
	case msgTypeSessionSetup:
		baseID, keyData, err := decodeSessionSetupDeliveryPayload(shardData[1:])
		if err != nil {
			return
		}
		baseObs.MessageType = "session-setup"
		baseObs.BaseSessionID = baseID
		m.recordFinalDeliveryObservation(baseObs)
		m.destHandler.ensureSession(baseID)
		if err := m.destHandler.StoreSessionSetup(baseID, keyData); err != nil {
			return
		}
		return
	case msgTypeSessionData:
		baseID, hasSeq, seq, shard, totalShards, authTag, err := decodeSessionDataFramePayload(shardData[1:])
		if err != nil {
			return
		}
		sessionID := routedSessionID(baseID, hasSeq, seq)
		baseObs.MessageType = "session-data"
		baseObs.BaseSessionID = baseID
		baseObs.SessionID = sessionID
		m.recordFinalDeliveryObservation(baseObs)
		m.destHandler.ensureSession(sessionID)
		if err := m.destHandler.AddShard(sessionID, shard, nil, authTag, totalShards); err != nil {
			return
		}
		data, err := m.destHandler.TryReconstruct(sessionID)
		if err != nil {
			return
		}
		m.destHandler.deliverSessionData(sessionID, data)
		select {
		case m.destHandler.dataCh <- data:
		default:
		}
		return
	case msgTypeSessionClose:
		baseID, err := decodeSessionCloseFramePayload(shardData[1:])
		if err == nil {
			baseObs.MessageType = "session-close"
			baseObs.BaseSessionID = baseID
			m.recordFinalDeliveryObservation(baseObs)
			m.destHandler.ClearSessionSetup(baseID)
			m.destHandler.unregisterSession(baseID)
		}
		return
	default:
		return
	}

	// Parse data payload (msgType already stripped by relay).
	sessionID, shard, keyData, authTag, totalShards, err := m.parseShardPayload(shardData[1:])
	if err != nil {
		if os.Getenv("LIBP2P_MIXNET_BENCH_DEBUG") != "" {
			log.Printf("[mixnet bench host=%s] parse shard failed: %v", m.host.ID(), err)
		}
		return
	}

	// Ensure session registration for inbound consumers.
	m.destHandler.ensureSession(sessionID)

	// Add to buffer with correct session ID (not hardcoded "default")
	if err := m.destHandler.AddShard(sessionID, shard, keyData, authTag, totalShards); err != nil {
		if os.Getenv("LIBP2P_MIXNET_BENCH_DEBUG") != "" {
			log.Printf("[mixnet bench host=%s] add shard failed: %v", m.host.ID(), err)
		}
		return
	}

	// Check if we can reconstruct using the correct session ID
	data, err := m.destHandler.TryReconstruct(sessionID)
	if err != nil {
		if os.Getenv("LIBP2P_MIXNET_BENCH_DEBUG") != "" {
			log.Printf("[mixnet bench host=%s] reconstruct pending session=%s shard=%d total=%d key=%t err=%v", m.host.ID(), sessionID, shard.Index, totalShards, len(keyData) > 0, err)
		}
		return
	}

	// Successfully got data
	m.destHandler.deliverSessionData(sessionID, data)
	select {
	case m.destHandler.dataCh <- data:
	default:
	}
}

// parseShardPayload parses shard data including session ID.
func (m *Mixnet) parseShardPayload(data []byte) (string, *ces.Shard, []byte, []byte, int, error) {
	header, payload, err := DecodePrivacyShard(data)
	if err != nil {
		return "", nil, nil, nil, 0, err
	}
	sessionID := string(header.SessionID)
	idx := int(header.ShardIndex)
	return sessionID, &ces.Shard{
		Index: idx,
		Data:  payload,
	}, header.KeyData, header.AuthTag, int(header.TotalShards), nil
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

func (h *DestinationHandler) StoreSessionSetup(baseSessionID string, keyData []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(keyData) == 0 {
		return fmt.Errorf("missing session setup key data")
	}
	key, err := decodeSessionKeyData(keyData)
	if err != nil {
		return err
	}
	h.setupKeyData[baseSessionID] = append([]byte(nil), keyData...)
	h.setupKeys[baseSessionID] = key
	timeout := h.routeTimeout
	if timeout <= 0 {
		timeout = h.timeout
	}
	if _, exists := h.setupTimers[baseSessionID]; !exists {
		h.setupTimers[baseSessionID] = time.AfterFunc(timeout, func() {
			h.mu.Lock()
			defer h.mu.Unlock()
			delete(h.setupKeyData, baseSessionID)
			delete(h.setupKeys, baseSessionID)
			if t, ok := h.setupTimers[baseSessionID]; ok {
				t.Stop()
				delete(h.setupTimers, baseSessionID)
			}
		})
	} else {
		h.setupTimers[baseSessionID].Reset(timeout)
	}
	return nil
}

func (h *DestinationHandler) ClearSessionSetup(baseSessionID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.setupKeyData, baseSessionID)
	delete(h.setupKeys, baseSessionID)
	delete(h.sessionDone, baseSessionID)
	if t, ok := h.setupTimers[baseSessionID]; ok {
		t.Stop()
		delete(h.setupTimers, baseSessionID)
	}
}

func (h *DestinationHandler) sessionKeyFor(sessionID string) (sessionKey, bool) {
	if key, ok := h.keys[sessionID]; ok {
		return key, true
	}
	key, ok := h.setupKeys[baseSessionID(sessionID)]
	return key, ok
}

func (h *DestinationHandler) sessionKeyDataFor(sessionID string) ([]byte, bool) {
	if keyData, ok := h.keyData[sessionID]; ok {
		return keyData, true
	}
	keyData, ok := h.setupKeyData[baseSessionID(sessionID)]
	return keyData, ok
}

func (h *DestinationHandler) inlineKeyDataFor(sessionID string) ([]byte, bool) {
	keyData, ok := h.keyData[sessionID]
	return keyData, ok
}

// AddShard adds an incoming shard to the destination's buffer for the given session.
func (h *DestinationHandler) AddShard(sessionID string, shard *ces.Shard, keyData []byte, authTag []byte, totalShards int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sessionCompletedLocked(sessionID) {
		return nil
	}
	if totalShards > 0 {
		h.totalShards[sessionID] = totalShards
	}
	if _, exists := h.timers[sessionID]; !exists {
		h.timers[sessionID] = time.AfterFunc(h.timeout, func() {
			h.mu.Lock()
			defer h.mu.Unlock()
			delete(h.shardBuf, sessionID)
			delete(h.shardTags, sessionID)
			delete(h.totalShards, sessionID)
			delete(h.keyData, sessionID)
			delete(h.sessionPending, baseSessionID(sessionID))
			delete(h.sessionNextSeq, baseSessionID(sessionID))
			if t, ok := h.timers[sessionID]; ok {
				t.Stop()
				delete(h.timers, sessionID)
			}
			delete(h.keys, sessionID)
			h.closeSessionLocked(sessionID)
		})
	}
	if len(keyData) > 0 {
		h.keyData[sessionID] = append([]byte(nil), keyData...)
		if key, err := decodeSessionKeyData(keyData); err == nil {
			h.keys[sessionID] = key
		}
	}
	if h.pipeline == nil && shard != nil {
		key, ok := h.sessionKeyFor(sessionID)
		if ok && (key.Mode == sessionCryptoModePerShard || key.Mode == sessionCryptoModePerShardStream) {
			if h.authEnabled {
				if len(authTag) == 0 {
					return ErrEncryptionFailed(fmt.Sprintf("missing auth tag for shard %d", shard.Index))
				}
				keyPayload, hasKeyPayload := h.inlineKeyDataFor(sessionID)
				includeKeys := len(keyData) > 0 || hasKeyPayload
				var payload []byte
				if includeKeys {
					if len(keyData) > 0 {
						payload = keyData
					} else {
						payload = keyPayload
					}
				}
				expected := computeAuthTag(key, []byte(sessionID), uint32(shard.Index), uint32(totalShards), shard.Data, includeKeys, payload, h.authTagSize)
				if !hmacEqual(authTag, expected) {
					return ErrEncryptionFailed(fmt.Sprintf("auth tag mismatch for shard %d", shard.Index))
				}
			}
			decrypted, err := decryptSessionShardPayloadWithKey(shard.Data, key, shard.Index, sessionID)
			if err != nil {
				return ErrEncryptionFailed(fmt.Sprintf("session shard decrypt failed for shard %d", shard.Index)).WithCause(err)
			}
			shard = &ces.Shard{Index: shard.Index, Data: decrypted}
			authTag = nil
		}
	}
	if h.authEnabled && shard != nil && authTag != nil {
		if h.shardTags[sessionID] == nil {
			h.shardTags[sessionID] = make(map[int][]byte)
		}
		h.shardTags[sessionID][shard.Index] = append([]byte(nil), authTag...)
	}
	if h.shardBuf[sessionID] == nil {
		h.shardBuf[sessionID] = make(map[int]*ces.Shard)
	}
	h.shardBuf[sessionID][shard.Index] = shard
	return nil
}

// TryReconstruct attempts to reconstruct the original data from buffered shards.
func (h *DestinationHandler) TryReconstruct(sessionID string) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	shardsByIndex := h.shardBuf[sessionID]
	shardCount := len(shardsByIndex)

	var (
		decrypted []byte
		err       error
	)
	if h.pipeline == nil {
		key, ok := h.sessionKeyFor(sessionID)
		if !ok {
			if _, hasFirstShard := shardsByIndex[0]; !hasFirstShard {
				return nil, ErrReconstructionMissingShards(sessionID, shardCount, h.threshold, []int{0})
			}
			return nil, ErrEncryptionFailed(fmt.Sprintf("missing session key for %s", sessionID))
		}
		// CES disabled: require all shards and concatenate in index order.
		total := h.totalShards[sessionID]
		if total <= 0 {
			total = shardCount
		}
		missing := missingShardIndexes(shardsByIndex, total)
		if shardCount < total {
			return nil, ErrReconstructionMissingShards(sessionID, shardCount, total, missing)
		}
		if total == 1 {
			sh := shardsByIndex[0]
			if sh == nil {
				return nil, ErrReconstructionMissingShards(sessionID, shardCount, total, missing)
			}
			if key.Mode == sessionCryptoModePerShard || key.Mode == sessionCryptoModePerShardStream {
				decrypted = sh.Data
			} else {
				if h.authEnabled {
					if err := h.verifyAuthTags(sessionID, shardsByIndex, total, key); err != nil {
						return nil, err
					}
				}
				decrypted, err = decryptSessionPayloadWithKey(sh.Data, key, sessionID)
				if err != nil {
					return nil, ErrEncryptionFailed("session decrypt failed").WithCause(err)
				}
			}
		} else {
			combinedLen := 0
			for i := 0; i < total; i++ {
				sh := shardsByIndex[i]
				if sh == nil {
					return nil, ErrReconstructionMissingShards(sessionID, shardCount, total, missing)
				}
				combinedLen += len(sh.Data)
			}
			combined := make([]byte, combinedLen)
			offset := 0
			for i := 0; i < total; i++ {
				sh := shardsByIndex[i]
				offset += copy(combined[offset:], sh.Data)
			}
			if key.Mode == sessionCryptoModePerShard || key.Mode == sessionCryptoModePerShardStream {
				decrypted = combined
			} else {
				if h.authEnabled {
					if err := h.verifyAuthTags(sessionID, shardsByIndex, total, key); err != nil {
						return nil, err
					}
				}
				decrypted, err = decryptSessionPayloadWithKey(combined, key, sessionID)
				if err != nil {
					return nil, ErrEncryptionFailed("session decrypt failed").WithCause(err)
				}
			}
		}
	} else {
		key, ok := h.sessionKeyFor(sessionID)
		if !ok {
			if _, hasFirstShard := shardsByIndex[0]; !hasFirstShard {
				return nil, ErrReconstructionMissingShards(sessionID, shardCount, h.threshold, []int{0})
			}
			return nil, ErrEncryptionFailed(fmt.Sprintf("missing session key for %s", sessionID))
		}
		total := h.totalShards[sessionID]
		if total <= 0 {
			total = h.pipeline.Sharder().TotalShards()
		}
		missing := missingShardIndexes(shardsByIndex, total)
		if shardCount < h.threshold {
			return nil, ErrReconstructionMissingShards(sessionID, shardCount, h.threshold, missing)
		}
		if h.authEnabled {
			if err := h.verifyAuthTags(sessionID, shardsByIndex, total, key); err != nil {
				return nil, err
			}
		}
		unique := make([]*ces.Shard, 0, shardCount)
		for _, sh := range shardsByIndex {
			if sh != nil {
				unique = append(unique, sh)
			}
		}
		encrypted, err := h.pipeline.Sharder().Reconstruct(unique)
		if err != nil {
			return nil, ErrShardingFailed(fmt.Sprintf("reconstruction failed for session %s missing_shard_ids=%v", sessionID, missing)).WithCause(err)
		}
		decrypted, err = decryptSessionPayloadWithKey(encrypted, key, sessionID)
		if err != nil {
			return nil, ErrEncryptionFailed("session decrypt failed").WithCause(err)
		}
	}

	data := decrypted
	if h.useLengthPrefix {
		data, err = stripLengthPrefix(data)
		if err != nil {
			return nil, ErrProtocolError("invalid length prefix").WithCause(err)
		}
	}
	if h.pipeline != nil {
		data, err = h.pipeline.Compressor().Decompress(data)
		if err != nil {
			return nil, err
		}
	}

	if t, ok := h.timers[sessionID]; ok {
		t.Stop()
		delete(h.timers, sessionID)
	}
	h.markSessionCompletedLocked(sessionID)
	delete(h.shardBuf, sessionID)
	delete(h.shardTags, sessionID)
	delete(h.keys, sessionID)
	delete(h.keyData, sessionID)
	delete(h.totalShards, sessionID)
	return data, nil
}

func (h *DestinationHandler) verifyAuthTags(sessionID string, shardsByIndex map[int]*ces.Shard, total int, key sessionKey) error {
	tags := h.shardTags[sessionID]
	if tags == nil {
		return ErrEncryptionFailed(fmt.Sprintf("missing auth tags for %s", sessionID))
	}
	keyPayload, _ := h.inlineKeyDataFor(sessionID)
	for _, sh := range shardsByIndex {
		tag, ok := tags[sh.Index]
		if !ok {
			return ErrEncryptionFailed(fmt.Sprintf("missing auth tag for shard %d", sh.Index))
		}
		includeKeys := len(keyPayload) > 0
		var payload []byte
		if includeKeys {
			payload = keyPayload
		}
		expected := computeAuthTag(key, []byte(sessionID), uint32(sh.Index), uint32(total), sh.Data, includeKeys, payload, h.authTagSize)
		if !hmacEqual(tag, expected) {
			return ErrEncryptionFailed(fmt.Sprintf("auth tag mismatch for shard %d", sh.Index))
		}
	}
	return nil
}

func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func (h *DestinationHandler) sessionCompletedLocked(sessionID string) bool {
	if h.reusableBaseSessionLocked(sessionID) {
		return false
	}
	if h.sessionDone == nil {
		return false
	}
	expiry, ok := h.sessionDone[sessionID]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		delete(h.sessionDone, sessionID)
		return false
	}
	return true
}

func (h *DestinationHandler) markSessionCompletedLocked(sessionID string) {
	if h.reusableBaseSessionLocked(sessionID) {
		return
	}
	if h.sessionDone == nil {
		h.sessionDone = make(map[string]time.Time)
	}
	h.sessionDone[sessionID] = time.Now().Add(h.timeout)
}

func (h *DestinationHandler) reusableBaseSessionLocked(sessionID string) bool {
	baseID := baseSessionID(sessionID)
	if sessionID != baseID {
		return false
	}
	_, ok := h.setupKeys[baseID]
	return ok
}

func (h *DestinationHandler) registerSession(sessionID string) chan []byte {
	sessionID = baseSessionID(sessionID)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sessionPending == nil {
		h.sessionPending = make(map[string]map[uint64][]byte)
	}
	if h.sessionNextSeq == nil {
		h.sessionNextSeq = make(map[string]uint64)
	}
	if mailbox, ok := h.sessions[sessionID]; ok {
		return mailbox.ch
	}
	mailbox := &sessionMailbox{ch: make(chan []byte, sessionChannelBuffer)}
	h.sessions[sessionID] = mailbox
	h.sessionNextSeq[sessionID] = 0
	return mailbox.ch
}

func (h *DestinationHandler) ensureSession(sessionID string) {
	h.mu.Lock()
	if h.sessionCompletedLocked(sessionID) {
		h.mu.Unlock()
		return
	}
	sessionID = baseSessionID(sessionID)
	if h.sessionPending == nil {
		h.sessionPending = make(map[string]map[uint64][]byte)
	}
	if h.sessionNextSeq == nil {
		h.sessionNextSeq = make(map[string]uint64)
	}
	if _, ok := h.sessions[sessionID]; !ok {
		h.sessions[sessionID] = &sessionMailbox{ch: make(chan []byte, sessionChannelBuffer)}
		h.sessionNextSeq[sessionID] = 0
		select {
		case h.inboundCh <- sessionID:
		default:
		}
	}
	h.mu.Unlock()
}

func (h *DestinationHandler) unregisterSession(sessionID string) {
	sessionID = baseSessionID(sessionID)
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.keys, sessionID)
	delete(h.keyData, sessionID)
	delete(h.sessionDone, sessionID)
	if t, ok := h.timers[sessionID]; ok {
		t.Stop()
		delete(h.timers, sessionID)
	}
	delete(h.setupKeys, sessionID)
	delete(h.setupKeyData, sessionID)
	if t, ok := h.setupTimers[sessionID]; ok {
		t.Stop()
		delete(h.setupTimers, sessionID)
	}
	h.closeSessionLocked(sessionID)
}

func (h *DestinationHandler) deliverSessionData(sessionID string, data []byte) {
	baseID, seq, hasSeq := parseStreamWriteSequence(sessionID)
	sessionID = baseSessionID(sessionID)
	h.mu.Lock()
	mailbox, ok := h.sessions[sessionID]
	if !ok {
		h.mu.Unlock()
		return
	}
	mailbox.sendMu.Lock()
	if !hasSeq {
		h.mu.Unlock()
		if !mailbox.closed {
			mailbox.ch <- data
		}
		mailbox.sendMu.Unlock()
		return
	}
	if h.sessionPending == nil {
		h.sessionPending = make(map[string]map[uint64][]byte)
	}
	if h.sessionNextSeq == nil {
		h.sessionNextSeq = make(map[string]uint64)
	}
	pending := h.sessionPending[baseID]
	next := h.sessionNextSeq[baseID]
	toSend := make([][]byte, 0, 1)
	if seq == next && len(pending) == 0 {
		h.sessionNextSeq[baseID] = next + 1
		h.mu.Unlock()
		if !mailbox.closed {
			mailbox.ch <- data
		}
		mailbox.sendMu.Unlock()
		return
	}
	if pending == nil {
		pending = make(map[uint64][]byte)
		h.sessionPending[baseID] = pending
	}
	pending[seq] = data
	for {
		queued, ok := pending[next]
		if !ok {
			break
		}
		toSend = append(toSend, queued)
		delete(pending, next)
		next++
	}
	h.sessionNextSeq[baseID] = next
	if len(pending) == 0 {
		delete(h.sessionPending, baseID)
	}
	h.mu.Unlock()
	if !mailbox.closed {
		for _, queued := range toSend {
			mailbox.ch <- queued
		}
	}
	mailbox.sendMu.Unlock()
}

func (h *DestinationHandler) closeSessionLocked(sessionID string) {
	mailbox, ok := h.sessions[sessionID]
	if !ok {
		return
	}
	delete(h.sessions, sessionID)
	delete(h.sessionPending, sessionID)
	delete(h.sessionNextSeq, sessionID)
	mailbox.sendMu.Lock()
	defer mailbox.sendMu.Unlock()
	if mailbox.closed {
		return
	}
	close(mailbox.ch)
	mailbox.closed = true
}

// DataChan returns a channel that receives reconstructed data.
func (h *DestinationHandler) DataChan() <-chan []byte {
	return h.dataCh
}

// Close shuts down the Mixnet instance and releases all resources.
func (m *Mixnet) Close() error {
	// Idempotency: check if already closed
	if !m.closed.CompareAndSwap(false, true) {
		return nil // Already closed
	}

	// Cancel origin context to stop new operations
	if m.originCancel != nil {
		m.originCancel()
	}

	if m.failureNotifier != nil {
		if err := m.failureNotifier.Stop(); err != nil {
			log.Printf("[mixnet] failure notifier stop error: %v", err)
		}
	}

	// Stop the destination handler goroutine (Req 18).
	if m.destHandler != nil && m.destHandler.stopCh != nil {
		close(m.destHandler.stopCh)
	}
	if m.resourceMgr != nil {
		m.resourceMgr.Stop()
	}

	// Clear buffered shards.
	if m.destHandler != nil {
		m.destHandler.mu.Lock()
		for sessionID := range m.destHandler.shardBuf {
			delete(m.destHandler.shardBuf, sessionID)
		}
		for sessionID := range m.destHandler.totalShards {
			delete(m.destHandler.totalShards, sessionID)
		}
		for sessionID, timer := range m.destHandler.timers {
			if timer != nil {
				timer.Stop()
			}
			delete(m.destHandler.timers, sessionID)
		}
		for sessionID, timer := range m.destHandler.setupTimers {
			if timer != nil {
				timer.Stop()
			}
			delete(m.destHandler.setupTimers, sessionID)
		}
		for sessionID := range m.destHandler.keys {
			delete(m.destHandler.keys, sessionID)
		}
		for sessionID := range m.destHandler.keyData {
			delete(m.destHandler.keyData, sessionID)
		}
		for sessionID := range m.destHandler.setupKeys {
			delete(m.destHandler.setupKeys, sessionID)
		}
		for sessionID := range m.destHandler.setupKeyData {
			delete(m.destHandler.setupKeyData, sessionID)
		}
		for sessionID := range m.destHandler.sessions {
			m.destHandler.closeSessionLocked(sessionID)
		}
		m.destHandler.mu.Unlock()
	}

	// Unregister the protocol handler (Req 12).
	m.host.RemoveStreamHandler(ProtocolID)

	if os.Getenv("MIXNET_FAST_CLOSE") == "1" {
		err := m.circuitMgr.Close()
		if m.pipeline != nil {
			m.pipeline.Encrypter().SecureErase()
		}
		m.clearCircuitKeys()
		m.clearAllStreamSessions()
		for range m.activeConnections {
			m.metrics.CircuitClosed()
		}
		if err != nil {
			return ErrCircuitFailed("failed to close circuit manager").WithCause(err)
		}
		return nil
	}

	// Send close signal through all active circuits and wait for acknowledgment (Req 18)
	m.mu.RLock()
	var closeSignals []string
	for dest := range m.activeConnections {
		circuits := m.activeConnections[dest]
		for _, c := range circuits {
			closeSignals = append(closeSignals, c.ID)
		}
	}
	m.mu.RUnlock()

	// Wait for acknowledgments with timeout (Req 18.2)
	// Use libp2p's stream close semantics properly - close each circuit and wait for completion
	ackTimeout := 10 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), ackTimeout)
	defer cancel()

	// Close all circuits and collect errors
	var closeErrors []error
	var closeErrMu sync.Mutex
	var wg sync.WaitGroup

	for _, circuitID := range closeSignals {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			if err := m.sendCloseAndWait(ctx, id); err != nil {
				// Close acknowledgements are best-effort. We log timeouts/failures
				// but still proceed with shutdown so Close() remains reliable.
				log.Printf("[mixnet] close ack failed for circuit %s: %v", id, err)
			}
			// Close the circuit and wait for completion
			closeCtx, closeCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer closeCancel()
			if err := m.circuitMgr.CloseCircuitWithContext(closeCtx, id); err != nil {
				closeErrMu.Lock()
				closeErrors = append(closeErrors, ErrCircuitFailed(fmt.Sprintf("failed to close circuit %s", id)).WithCause(err))
				closeErrMu.Unlock()
			}
		}(circuitID)
	}

	wg.Wait()

	// Check for context timeout (Req 18.5)
	if ctx.Err() == context.DeadlineExceeded {
		// Log timeout but don't fail - circuits will be cleaned up eventually
		log.Printf("[mixnet] close acknowledgment timeout after %v", ackTimeout)
	}

	// Close underlying circuit manager
	err := m.circuitMgr.Close()

	// Securely erase all cryptographic material (Req 18.4)
	if m.pipeline != nil {
		m.pipeline.Encrypter().SecureErase()
	}
	m.clearCircuitKeys()
	m.clearAllStreamSessions()

	// Mark metrics
	for range m.activeConnections {
		m.metrics.CircuitClosed()
	}

	if err != nil {
		closeErrors = append(closeErrors, ErrCircuitFailed("failed to close circuit manager").WithCause(err))
	}
	if len(closeErrors) > 0 {
		return ErrCircuitFailed(fmt.Sprintf("failed to close mixnet cleanly (%d errors)", len(closeErrors))).WithCause(errors.Join(closeErrors...))
	}
	return nil
}

func (m *Mixnet) ensureCircuitKeys(ctx context.Context, circuits []*circuit.Circuit) error {
	var wg sync.WaitGroup
	errCh := make(chan error, len(circuits))

	for _, c := range circuits {
		c := c
		if c == nil {
			continue
		}
		keyID := m.circuitKeyID(c)
		if keys, ok := m.getCircuitKeys(keyID); ok && len(keys) == len(c.Peers) {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			keys, err := m.establishCircuitKeys(ctx, c)
			if err != nil {
				errCh <- err
				return
			}
			m.setCircuitKeys(keyID, keys)
		}()
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

func (m *Mixnet) establishCircuitKeys(ctx context.Context, c *circuit.Circuit) ([][]byte, error) {
	if c == nil || len(c.Peers) == 0 {
		return nil, fmt.Errorf("invalid circuit")
	}
	keyID := m.circuitKeyID(c)
	keys := make([][]byte, len(c.Peers))
	for i, p := range c.Peers {
		key, err := m.exchangeHopKey(ctx, p, keyID)
		if err != nil {
			return nil, fmt.Errorf("key exchange failed for %s: %w", p, err)
		}
		keys[i] = key
	}
	return keys, nil
}

func (m *Mixnet) setCircuitKeys(circuitID string, keys [][]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.circuitKeys[circuitID] = keys
}

func (m *Mixnet) getCircuitKeys(circuitID string) ([][]byte, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	keys, ok := m.circuitKeys[circuitID]
	return keys, ok
}

func (m *Mixnet) clearCircuitKeys() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, keys := range m.circuitKeys {
		for i := range keys {
			ces.SecureEraseBytes(keys[i])
			keys[i] = nil
		}
		delete(m.circuitKeys, id)
	}
}

func (m *Mixnet) clearAllStreamSessions() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, key := range m.streamSessions {
		ces.SecureEraseBytes(key.Key)
		ces.SecureEraseBytes(key.Nonce)
		delete(m.streamSessions, id)
	}
}

func (m *Mixnet) circuitKeyID(c *circuit.Circuit) string {
	if c == nil {
		return ""
	}
	return fmt.Sprintf("%s/%s", m.host.ID(), c.ID)
}

func (m *Mixnet) sendCloseAndWait(ctx context.Context, circuitID string) error {
	c, ok := m.circuitMgr.GetCircuit(circuitID)
	if !ok {
		return fmt.Errorf("circuit not found: %s", circuitID)
	}
	dest, ok := m.destinationForCircuit(circuitID)
	if !ok {
		return fmt.Errorf("destination not found for circuit %s", circuitID)
	}
	stream, ok := m.circuitMgr.GetStream(circuitID)
	if !ok || stream == nil {
		return fmt.Errorf("stream not found for circuit %s", circuitID)
	}

	keyID := m.circuitKeyID(c)
	keys, ok := m.getCircuitKeys(keyID)
	if !ok {
		var err error
		keys, err = m.establishCircuitKeys(ctx, c)
		if err != nil {
			return fmt.Errorf("missing hop keys for circuit %s: %w", circuitID, err)
		}
		m.setCircuitKeys(keyID, keys)
	}
	encryptedPayload, err := encryptOnion([]byte{msgTypeCloseReq}, c, dest, keys)
	if err != nil {
		return err
	}
	fullData, err := encodeEncryptedFrameWithVersion(keyID, frameVersionFullOnion, encryptedPayload)
	if err != nil {
		return err
	}

	if err := m.circuitMgr.SendData(circuitID, fullData); err != nil {
		return err
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.Stream().SetReadDeadline(deadline)
	} else {
		_ = stream.Stream().SetReadDeadline(time.Now().Add(10 * time.Second))
	}

	buf := make([]byte, 1)
	if _, err := stream.Stream().Read(buf); err != nil {
		return err
	}
	if buf[0] != msgTypeCloseAck {
		return fmt.Errorf("unexpected close ack: %x", buf[0])
	}
	return nil
}

func (m *Mixnet) destinationForCircuit(circuitID string) (peer.ID, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for dest, circuits := range m.activeConnections {
		for _, c := range circuits {
			if c != nil && c.ID == circuitID {
				return dest, true
			}
		}
	}
	return "", false
}

// CircuitManager returns the instance of the circuit manager.
func (m *Mixnet) CircuitManager() *circuit.CircuitManager {
	return m.circuitMgr
}

// SetDeliveryObservationHandler registers an optional callback that receives
// final-hop delivery observations for diagnostics and benchmark proof capture.
func (m *Mixnet) SetDeliveryObservationHandler(fn func(FinalDeliveryObservation)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.observeDelivery = fn
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

func (m *Mixnet) recordFinalDeliveryObservation(obs FinalDeliveryObservation) {
	m.mu.RLock()
	fn := m.observeDelivery
	m.mu.RUnlock()
	if fn == nil {
		return
	}
	fn(obs)
}

func previewHexBytes(data []byte) string {
	const previewLimit = 24
	if len(data) == 0 {
		return ""
	}
	if len(data) > previewLimit {
		data = data[:previewLimit]
	}
	out := make([]byte, 0, len(data)*3)
	for i, b := range data {
		if i > 0 {
			out = append(out, ' ')
		}
		out = append(out, "0123456789abcdef"[b>>4], "0123456789abcdef"[b&0x0f])
	}
	return string(out)
}

func previewTextBytes(data []byte) string {
	const previewLimit = 24
	if len(data) == 0 {
		return ""
	}
	if len(data) > previewLimit {
		data = data[:previewLimit]
	}
	out := make([]byte, len(data))
	for i, b := range data {
		if b >= 32 && b <= 126 {
			out[i] = b
			continue
		}
		out[i] = '.'
	}
	return string(out)
}

// RecoverFromFailure attempts to rebuild failed circuits to maintain the reconstruction threshold.
func (m *Mixnet) RecoverFromFailure(ctx context.Context, dest peer.ID) error {
	m.mu.RLock()
	circuits, ok := m.activeConnections[dest]
	m.mu.RUnlock()
	if !ok {
		return ErrCircuitFailed(fmt.Sprintf("no active connection to %s", dest))
	}

	threshold := m.config.GetErasureThreshold()
	targetCircuits := m.config.CircuitCount
	m.metrics.RecordRecovery()

	for attempt := 0; ; attempt++ {
		if ctx.Err() != nil {
			return ErrCircuitFailed(fmt.Sprintf("recovery timed out after %d attempts", attempt)).WithCause(ctx.Err())
		}

		// Quarantine entry relays used by non-active circuits for this recovery
		// pass so we don't keep reusing relays that likely just failed.
		quarantinedRelays := make(map[peer.ID]struct{})
		for _, c := range circuits {
			if c == nil || c.IsActive() {
				continue
			}
			if entry := c.Entry(); entry != "" {
				quarantinedRelays[entry] = struct{}{}
			}
		}

		// Discover fresh relays so we don't rebuild with stale/failed ones (Req 10.3).
		newRelays, err := m.discoverRelays(ctx, dest)
		if err != nil {
			return ErrDiscoveryFailed("failed to discover relays for recovery").WithCause(err)
		}
		if len(quarantinedRelays) > 0 {
			filtered := make([]circuit.RelayInfo, 0, len(newRelays))
			for _, r := range newRelays {
				if _, blocked := quarantinedRelays[r.PeerID]; blocked {
					continue
				}
				filtered = append(filtered, r)
			}
			newRelays = filtered
		}
		// Update the circuit manager relay pool with freshly discovered relays.
		m.circuitMgr.UpdateRelayPool(newRelays)

		poolContains := make(map[peer.ID]struct{}, len(newRelays))
		for _, r := range newRelays {
			poolContains[r.PeerID] = struct{}{}
		}
		// If any active circuit still contains a relay that was dropped from discovery,
		// mark it failed so it can be rebuilt.
		for i, c := range circuits {
			if c == nil || !c.IsActive() {
				continue
			}
			for _, p := range c.Peers {
				if _, quarantined := quarantinedRelays[p]; quarantined {
					m.circuitMgr.MarkCircuitFailed(c.ID)
					_ = m.circuitMgr.CloseCircuit(c.ID)
					circuits[i] = c
					break
				}
				if _, ok := poolContains[p]; !ok {
					m.circuitMgr.MarkCircuitFailed(c.ID)
					_ = m.circuitMgr.CloseCircuit(c.ID)
					circuits[i] = c
					break
				}
			}
		}

		for i, c := range circuits {
			if c == nil {
				continue
			}
			if !c.IsActive() {
				newCircuit, err := m.circuitMgr.RebuildCircuit(c.ID)
				if err != nil {
					continue
				}
				err = m.circuitMgr.EstablishCircuit(newCircuit, dest, relay.ProtocolID)
				if err != nil {
					continue
				}
				keys, err := m.establishCircuitKeys(ctx, newCircuit)
				if err != nil {
					_ = m.circuitMgr.CloseCircuit(newCircuit.ID)
					continue
				}
				m.setCircuitKeys(m.circuitKeyID(newCircuit), keys)
				m.circuitMgr.ActivateCircuit(newCircuit.ID)
				circuits[i] = newCircuit
				m.metrics.RecordCircuitSuccess()
			}
		}

		if adaptiveTarget := m.circuitMgr.AdaptiveTargetCircuitCount(len(newRelays)); adaptiveTarget > targetCircuits {
			targetCircuits = adaptiveTarget
		}

		if activeCount := m.circuitMgr.ActiveCircuitCount(); activeCount < targetCircuits {
			for activeCount < targetCircuits {
				extraCircuit, err := m.circuitMgr.BuildCircuit()
				if err != nil {
					break
				}
				if err := m.circuitMgr.EstablishCircuit(extraCircuit, dest, relay.ProtocolID); err != nil {
					_ = m.circuitMgr.CloseCircuit(extraCircuit.ID)
					break
				}
				keys, err := m.establishCircuitKeys(ctx, extraCircuit)
				if err != nil {
					_ = m.circuitMgr.CloseCircuit(extraCircuit.ID)
					break
				}
				m.setCircuitKeys(m.circuitKeyID(extraCircuit), keys)
				if err := m.circuitMgr.ActivateCircuit(extraCircuit.ID); err != nil {
					_ = m.circuitMgr.CloseCircuit(extraCircuit.ID)
					break
				}
				circuits = append(circuits, extraCircuit)
				m.metrics.RecordCircuitSuccess()
				activeCount = m.circuitMgr.ActiveCircuitCount()
			}
		}

		m.mu.Lock()
		m.activeConnections[dest] = circuits
		m.mu.Unlock()

		activeCount := m.circuitMgr.ActiveCircuitCount()
		if m.config.UseCESPipeline {
			if activeCount >= targetCircuits {
				break
			}
		} else if activeCount >= threshold {
			break
		}

		// Backoff a bit before trying again so discovery/state can settle.
		select {
		case <-time.After(250 * time.Millisecond):
		case <-ctx.Done():
			return ErrCircuitFailed(fmt.Sprintf("recovery timed out after %d attempts", attempt)).WithCause(ctx.Err())
		}
	}

	m.StartHeartbeatMonitoring(defaultHeartbeatInterval)

	if !m.circuitMgr.CanRecover() {
		m.metrics.RecordCircuitFailure()
		return ErrCircuitFailed(fmt.Sprintf("insufficient circuits after recovery: have %d, need %d", m.circuitMgr.ActiveCircuitCount(), threshold))
	}

	if err := m.reschedulePendingShards(ctx, dest); err != nil {
		return ErrCircuitFailed("failed to reschedule shards after recovery").WithCause(err)
	}

	return nil
}

func missingShardIndexes(shardsByIndex map[int]*ces.Shard, total int) []int {
	if total <= 0 {
		return nil
	}
	missing := make([]int, 0)
	for i := 0; i < total; i++ {
		if _, ok := shardsByIndex[i]; !ok {
			missing = append(missing, i)
		}
	}
	return missing
}

func cloneShards(shards []*ces.Shard) []*ces.Shard {
	out := make([]*ces.Shard, 0, len(shards))
	for _, sh := range shards {
		if sh == nil {
			continue
		}
		cp := make([]byte, len(sh.Data))
		copy(cp, sh.Data)
		out = append(out, &ces.Shard{Index: sh.Index, Data: cp})
	}
	return out
}

func cloneShardRefs(shards []*ces.Shard) []*ces.Shard {
	out := make([]*ces.Shard, 0, len(shards))
	for _, sh := range shards {
		if sh != nil {
			out = append(out, sh)
		}
	}
	return out
}

func activeCircuitSubset(circuits []*circuit.Circuit) []*circuit.Circuit {
	active := make([]*circuit.Circuit, 0, len(circuits))
	for _, c := range circuits {
		if c != nil && c.IsActive() {
			active = append(active, c)
		}
	}
	return active
}

func (m *Mixnet) setPendingTransmission(dest peer.ID, sessionID string, keyData []byte, shards []*ces.Shard, sessionRouting bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	keyCopy := make([]byte, len(keyData))
	copy(keyCopy, keyData)
	m.pendingShards[dest] = &PendingTransmission{
		SessionID:      sessionID,
		KeyData:        keyCopy,
		SessionRouting: sessionRouting,
		// Keep immutable shard references here and only deep-clone if recovery
		// actually needs to reschedule them. This avoids an eager full-payload
		// copy on every successful send.
		Shards:    cloneShardRefs(shards),
		CreatedAt: time.Now(),
	}
}

func (m *Mixnet) clearPendingTransmission(dest peer.ID, sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pt, ok := m.pendingShards[dest]
	if !ok || pt.SessionID != sessionID {
		return
	}
	delete(m.pendingShards, dest)
}

func (m *Mixnet) pendingTransmission(dest peer.ID) (*PendingTransmission, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	pt, ok := m.pendingShards[dest]
	if !ok {
		return nil, false
	}
	return &PendingTransmission{
		SessionID:      pt.SessionID,
		KeyData:        append([]byte(nil), pt.KeyData...),
		Shards:         cloneShards(pt.Shards),
		CreatedAt:      pt.CreatedAt,
		SessionRouting: pt.SessionRouting,
	}, true
}

func (m *Mixnet) activeCircuitsForDest(dest peer.ID) []*circuit.Circuit {
	m.mu.RLock()
	defer m.mu.RUnlock()
	all := m.activeConnections[dest]
	active := make([]*circuit.Circuit, 0, len(all))
	for _, c := range all {
		if c != nil && c.IsActive() {
			active = append(active, c)
		}
	}
	return active
}

func (m *Mixnet) reschedulePendingShards(ctx context.Context, dest peer.ID) error {
	pt, ok := m.pendingTransmission(dest)
	if !ok {
		return nil
	}
	circuits := m.activeCircuitsForDest(dest)
	if len(circuits) == 0 {
		return ErrCircuitFailed("no active circuits available for shard rescheduling")
	}
	if len(pt.Shards) != len(circuits) {
		return ErrShardingFailed(fmt.Sprintf("cannot reschedule shards: shards=%d active_circuits=%d", len(pt.Shards), len(circuits)))
	}
	var authKey *sessionKey
	if m.config.EnableAuthTag {
		decoded, err := decodeSessionKeyData(pt.KeyData)
		if err != nil {
			return ErrEncryptionFailed("auth key decode failed").WithCause(err)
		}
		authKey = &decoded
	}
	if pt.SessionRouting && sessionRoutingEnabled(m.config) {
		baseID, seq, hasSeq := parseStreamWriteSequence(pt.SessionID)
		if !hasSeq {
			baseID = pt.SessionID
		}
		m.resetRouteSetup(baseID)
		if err := m.sendSessionSetupAcrossCircuits(ctx, dest, baseID, pt.KeyData, circuits); err != nil {
			return err
		}
		if err := m.sendSessionDataAcrossCircuits(ctx, dest, baseID, hasSeq, seq, pt.SessionID, pt.KeyData, pt.Shards, circuits, authKey); err != nil {
			return err
		}
		m.clearPendingTransmission(dest, pt.SessionID)
		return nil
	}
	if err := m.sendShardsAcrossCircuits(ctx, dest, []byte(pt.SessionID), pt.KeyData, pt.Shards, circuits, authKey); err != nil {
		return err
	}
	m.clearPendingTransmission(dest, pt.SessionID)
	return nil
}

type shardSendResult struct {
	circuitID string
	err       error
}

func (m *Mixnet) sendShardsAcrossCircuits(ctx context.Context, dest peer.ID, sessionIDBytes []byte, keyData []byte, shards []*ces.Shard, circuits []*circuit.Circuit, authKey *sessionKey) error {
	sendCount := len(shards)
	resultCh := make(chan shardSendResult, sendCount)
	circuitIDs := make([]string, sendCount)
	paddingCfg := m.headerPaddingConfig()
	concurrencyLimit := sendCount
	sendSem := make(chan struct{}, concurrencyLimit)

	for i := 0; i < sendCount; i++ {
		// Apply jitter for all shards after the first to break timing correlations.
		// This prevents global observers from linking shards by correlating arrival times.
		if i > 0 && m.config.MaxJitter > 0 {
			var b [1]byte
			rand.Read(b[:])
			jitter := time.Duration(b[0]%uint8(m.config.MaxJitter)) * time.Millisecond
			select {
			case <-time.After(jitter):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		circuitID := circuits[i].ID
		circuitIDs[i] = circuitID
		shard := shards[i]

		go func(shardData []byte, circuitID string, idx int) {
			sendSem <- struct{}{}
			defer func() { <-sendSem }()

			shardIndex := shard.Index
			if shardIndex < 0 {
				shardIndex = idx
			}
			// Duplicate session key material on every shard so any threshold-sized
			// subset can be decrypted without depending on shard 0 arriving.
			includeKeys := len(keyData) > 0
			var keyPayload []byte
			if includeKeys {
				keyPayload = keyData
			}
			var authTag []byte
			if m.config.EnableAuthTag && authKey != nil {
				authTag = computeAuthTag(*authKey, sessionIDBytes, uint32(shardIndex), uint32(sendCount), shardData, includeKeys, keyPayload, m.config.AuthTagSize)
			}
			keyID := m.circuitKeyID(circuits[idx])
			hopKeys, ok := m.getCircuitKeys(keyID)
			if !ok {
				resultCh <- shardSendResult{circuitID: circuitID, err: ErrEncryptionFailed(fmt.Sprintf("missing hop keys for circuit %s", circuitID))}
				return
			}
			// Apply per-stream write deadline (Req 8.2).
			if stream, ok := m.circuitMgr.GetStream(circuitID); ok && stream != nil {
				stream.Stream().SetDeadline(time.Now().Add(configuredStreamTimeout(30 * time.Second)))
			}
			bytesSent := 0
			switch m.config.EncryptionMode {
			case EncryptionModeHeaderOnly:
				// Header-only mode keeps the shard payload in its end-to-end
				// encrypted form and only onion-wraps the control header used by
				// relays. The sender frames the final wire message in one
				// allocation so relays can later stream the payload through
				// without rebuilding another full copy.
				controlHeader, err := EncodePrivacyShard(nil, PrivacyShardHeader{
					SessionID:   sessionIDBytes,
					ShardIndex:  uint32(shardIndex),
					TotalShards: uint32(sendCount),
					HasKeys:     includeKeys,
					KeyData:     keyPayload,
					AuthTag:     authTag,
				}, paddingCfg)
				if err != nil {
					resultCh <- shardSendResult{circuitID: circuitID, err: ErrProtocolError("failed to encode control header").WithCause(err)}
					return
				}
				onionHeader, err := encryptOnionHeader(controlHeader, circuits[idx], dest, hopKeys)
				if err != nil {
					resultCh <- shardSendResult{circuitID: circuitID, err: ErrEncryptionFailed(fmt.Sprintf("failed to encrypt header for circuit %s", circuitID)).WithCause(err)}
					return
				}
				frameHeader, err := buildHeaderOnlyFrameHeader(keyID, len(onionHeader), len(shardData))
				if err != nil {
					resultCh <- shardSendResult{circuitID: circuitID, err: ErrProtocolError("failed to frame header-only shard").WithCause(err)}
					return
				}
				bytesSent = len(frameHeader) + len(onionHeader) + len(shardData)
				if err := m.circuitMgr.SendDataParts(circuitID, frameHeader, onionHeader, shardData); err != nil {
					resultCh <- shardSendResult{circuitID: circuitID, err: ErrTransportFailed(fmt.Sprintf("failed to send on circuit %s", circuitID)).WithCause(err)}
					return
				}
			default:
				privacyShard, err := EncodePrivacyShard(shardData, PrivacyShardHeader{
					SessionID:   sessionIDBytes,
					ShardIndex:  uint32(shardIndex),
					TotalShards: uint32(sendCount),
					HasKeys:     includeKeys,
					KeyData:     keyPayload,
					AuthTag:     authTag,
				}, paddingCfg)
				if err != nil {
					resultCh <- shardSendResult{circuitID: circuitID, err: ErrProtocolError("failed to encode privacy shard").WithCause(err)}
					return
				}
				shardPayload := append([]byte{msgTypeData}, privacyShard...)
				encryptedPayload, err := encryptOnion(shardPayload, circuits[idx], dest, hopKeys)
				if err != nil {
					resultCh <- shardSendResult{circuitID: circuitID, err: ErrEncryptionFailed(fmt.Sprintf("failed to encrypt shard for circuit %s", circuitID)).WithCause(err)}
					return
				}
				frameHeader, err := buildEncryptedFrameHeader(keyID, frameVersionFullOnion, len(encryptedPayload))
				if err != nil {
					resultCh <- shardSendResult{circuitID: circuitID, err: ErrProtocolError("failed to frame encrypted shard").WithCause(err)}
					return
				}
				bytesSent = len(frameHeader) + len(encryptedPayload)
				if err := m.circuitMgr.SendDataParts(circuitID, frameHeader, encryptedPayload); err != nil {
					resultCh <- shardSendResult{circuitID: circuitID, err: ErrTransportFailed(fmt.Sprintf("failed to send on circuit %s", circuitID)).WithCause(err)}
					return
				}
			}

			m.metrics.RecordThroughput(uint64(bytesSent))
			resultCh <- shardSendResult{}
		}(shard.Data, circuitID, i)
	}

	sendTimeout := configuredStreamTimeout(30 * time.Second)
	pendingByCircuit := make(map[string]int, len(circuits))
	for i := 0; i < sendCount; i++ {
		pendingByCircuit[circuitIDs[i]]++
	}

	progressTimer := time.NewTimer(sendTimeout)
	defer progressTimer.Stop()

	completed := 0
	var firstErr error
	var failedCircuitID string
	for completed < sendCount {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case result := <-resultCh:
			completed++
			if count := pendingByCircuit[result.circuitID]; count > 1 {
				pendingByCircuit[result.circuitID] = count - 1
			} else if count == 1 {
				delete(pendingByCircuit, result.circuitID)
			}
			if !progressTimer.Stop() {
				select {
				case <-progressTimer.C:
				default:
				}
			}
			progressTimer.Reset(sendTimeout)
			if result.err == nil {
				// A successful local write only means the shard made it onto the
				// circuit stream. It is not a delivery acknowledgement from the
				// far side, so the API must wait for every shard write attempt to
				// complete before reporting success.
				continue
			}
			if firstErr == nil {
				firstErr = result.err
				failedCircuitID = result.circuitID
			}
		case <-progressTimer.C:
			for circuitID := range pendingByCircuit {
				m.circuitMgr.MarkCircuitFailed(circuitID)
				_ = m.circuitMgr.CloseCircuit(circuitID)
			}
			return ErrTransportFailed("timed out waiting for shard sends")
		}
	}
	if firstErr != nil {
		if failedCircuitID != "" {
			m.circuitMgr.MarkCircuitFailed(failedCircuitID)
			_ = m.circuitMgr.CloseCircuit(failedCircuitID)
		}
		return firstErr
	}
	return nil
}

// Package mixnet provides a high-performance, metadata-private communication protocol for libp2p.
