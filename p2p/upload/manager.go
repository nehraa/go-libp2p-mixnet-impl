package upload

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/routing"
	"github.com/libp2p/go-libp2p/p2p/hub"
)

type ackKey struct {
	uploadID   string
	shardIndex int
}

// Manager orchestrates sender-side shard upload fan-out.
type Manager struct {
	cfg     Config
	host    host.Host
	routing routing.Routing

	transportMode hub.TransportMode
	hub           *hub.Hub
	mixnet        mixnetRuntime

	resolver      PeerResolver
	manifestStore SenderManifestStore

	ctx    context.Context
	cancel context.CancelFunc

	mu         sync.Mutex
	ackWaiters map[ackKey]chan ackFrame
	buffers    map[string][]byte
	active     map[string]struct{}

	wg sync.WaitGroup
}

// NewManager creates a sender upload manager backed by p2p/hub.
func NewManager(h host.Host, r routing.Routing, cfg Config) (*Manager, error) {
	if h == nil {
		return nil, fmt.Errorf("%w: host is required", ErrInvalidConfig)
	}
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	manager := &Manager{
		cfg:           normalized,
		host:          h,
		routing:       r,
		transportMode: normalized.HubConfig.TransportMode,
		ctx:           ctx,
		cancel:        cancel,
		ackWaiters:    make(map[ackKey]chan ackFrame),
		buffers:       make(map[string][]byte),
		active:        make(map[string]struct{}),
	}
	if manager.transportMode == hub.TransportModeMixnet {
		mixRuntime, createErr := createMixnetRuntime(h, r, normalized.HubConfig)
		if createErr != nil {
			cancel()
			return nil, createErr
		}
		manager.mixnet = mixRuntime
	} else {
		hubCfg := normalized.HubConfig
		hubCfg.ProtocolID = normalized.ProtocolID
		hb, createErr := hub.New(h, hubCfg)
		if createErr != nil {
			cancel()
			return nil, fmt.Errorf("create upload hub: %w", createErr)
		}
		manager.hub = hb
	}
	if normalized.Resolver != nil {
		manager.resolver = normalized.Resolver
	} else {
		manager.resolver = NewDiscoveryPeerResolver(
			h,
			r,
			normalized.DiscoveryNamespace,
			normalized.SelectionMode,
			normalized.SamplingSize,
			normalized.RandomnessFactor,
		)
	}
	if normalized.SenderManifestStore != nil {
		manager.manifestStore = normalized.SenderManifestStore
	} else {
		manager.manifestStore = NewFileSenderManifestStore(normalized.ManifestRoot)
	}

	if manager.hub != nil {
		manager.wg.Add(2)
		go func() {
			defer manager.wg.Done()
			manager.runEventLoop()
		}()
		go func() {
			defer manager.wg.Done()
			manager.runMetricsLoop()
		}()
	}

	return manager, nil
}

// Close stops background loops and closes the internal hub.
func (m *Manager) Close() error {
	m.cancel()
	m.wg.Wait()
	if m.hub != nil {
		return m.hub.Close()
	}
	if m.mixnet != nil {
		return m.mixnet.Close()
	}
	return nil
}

// Upload sends pre-sharded data to discovered or explicit peers.
func (m *Manager) Upload(ctx context.Context, req UploadRequest) (UploadResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	uploadID, err := normalizeUploadID(req.UploadID)
	if err != nil {
		return UploadResult{}, err
	}
	mode, err := m.cfg.effectiveSuccessMode(req.SuccessMode)
	if err != nil {
		return UploadResult{}, err
	}
	if err := m.beginUpload(uploadID); err != nil {
		return UploadResult{}, err
	}
	defer m.endUpload(uploadID)

	shards, err := scanShards(req.Buffer, req.Delimiter, req.ExpectedShardCount, m.cfg.AllowEmptyShards)
	if err != nil {
		return UploadResult{}, err
	}
	if len(shards) == 0 {
		return UploadResult{}, fmt.Errorf("%w: no shards discovered", ErrInvalidRequest)
	}

	peers, err := m.resolvePeers(ctx, req.TargetPeers, len(shards))
	if err != nil {
		return UploadResult{}, err
	}
	if len(peers) != len(shards) {
		return UploadResult{}, fmt.Errorf(
			"%w: peer count %d does not match shard count %d",
			ErrInvalidRequest,
			len(peers),
			len(shards),
		)
	}

	startedAt := time.Now().UTC()
	results := make([]ShardUploadResult, len(shards))
	var wg sync.WaitGroup
	errs := make(chan error, len(shards))
	sem := make(chan struct{}, m.maxConcurrency(len(shards)))
	if m.transportMode == hub.TransportModeMixnet {
		for i := range shards {
			i := i
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				results[i] = m.sendShardOverMixnet(ctx, uploadID, mode, shards[i], len(shards), peers[i], errs)
			}()
		}
		wg.Wait()
		close(errs)
	} else {
		receptors, createErr := m.createReceptors(ctx, peers)
		if createErr != nil {
			return UploadResult{}, createErr
		}
		defer m.cleanupReceptors(receptors)
		for i := range shards {
			i := i
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				results[i] = m.sendShard(ctx, uploadID, mode, shards[i], len(shards), peers[i], receptors[i], errs)
			}()
		}
		wg.Wait()
		close(errs)
	}

	var firstErr error
	for sendErr := range errs {
		if sendErr != nil && firstErr == nil {
			firstErr = sendErr
		}
	}

	selectedPeers := make([]string, 0, len(peers))
	for _, p := range peers {
		selectedPeers = append(selectedPeers, p.ID.String())
	}
	finishedAt := time.Now().UTC()
	manifest := &SenderManifest{
		UploadID:      uploadID,
		ProtocolID:    string(m.cfg.ProtocolID),
		SuccessMode:   mode,
		SelectedPeers: selectedPeers,
		Shards:        results,
		StartedAt:     startedAt,
		FinishedAt:    finishedAt,
	}

	manifestPath, nodeIDsPath, saveErr := m.manifestStore.SaveSenderManifest(ctx, manifest)
	if saveErr != nil {
		if firstErr == nil {
			firstErr = saveErr
		}
	}

	result := UploadResult{
		UploadID:      uploadID,
		ProtocolID:    string(m.cfg.ProtocolID),
		SuccessMode:   mode,
		SelectedPeers: selectedPeers,
		ShardResults:  results,
		ManifestPath:  manifestPath,
		NodeIDsPath:   nodeIDsPath,
		StartedAt:     startedAt,
		FinishedAt:    finishedAt,
	}
	return result, firstErr
}

func (m *Manager) sendShard(
	ctx context.Context,
	uploadID string,
	mode SuccessMode,
	shard ShardView,
	totalShards int,
	target peer.AddrInfo,
	receptor *hub.Receptor,
	errs chan<- error,
) ShardUploadResult {
	startedAt := time.Now().UTC()
	result := ShardUploadResult{
		Index:     shard.Index,
		PeerID:    target.ID.String(),
		Start:     shard.Start,
		End:       shard.End,
		Bytes:     len(shard.Data),
		Status:    "failed",
		StartedAt: startedAt,
	}

	framePrefix, err := encodeDataFramePrefix(uploadID, shard.Index, totalShards, len(shard.Data), m.cfg.MaxFrameSize)
	if err != nil {
		result.Error = err.Error()
		result.FinishedAt = time.Now().UTC()
		errs <- err
		return result
	}

	var ackCh chan ackFrame
	if mode == SuccessModeAckOnPersist {
		ackCh = make(chan ackFrame, 1)
		m.registerWaiter(ackKey{uploadID: uploadID, shardIndex: shard.Index}, ackCh)
		defer m.unregisterWaiter(ackKey{uploadID: uploadID, shardIndex: shard.Index})
	}

	if err := m.sendWithReconnect(ctx, receptor, framePrefix, shard.Data); err != nil {
		result.Error = err.Error()
		result.FinishedAt = time.Now().UTC()
		errs <- err
		return result
	}

	if mode == SuccessModeAckOnPersist {
		ack, waitErr := m.waitAck(ctx, ackCh)
		if waitErr != nil {
			result.Error = waitErr.Error()
			result.FinishedAt = time.Now().UTC()
			errs <- waitErr
			return result
		}
		if !ack.Accepted {
			waitErr = fmt.Errorf("receiver rejected shard %d: %s", shard.Index, ack.Message)
			result.Error = waitErr.Error()
			result.FinishedAt = time.Now().UTC()
			errs <- waitErr
			return result
		}
		result.Acked = true
	}

	result.Status = "success"
	result.FinishedAt = time.Now().UTC()
	return result
}

func (m *Manager) sendShardOverMixnet(
	ctx context.Context,
	uploadID string,
	mode SuccessMode,
	shard ShardView,
	totalShards int,
	target peer.AddrInfo,
	errs chan<- error,
) ShardUploadResult {
	startedAt := time.Now().UTC()
	result := ShardUploadResult{
		Index:     shard.Index,
		PeerID:    target.ID.String(),
		Start:     shard.Start,
		End:       shard.End,
		Bytes:     len(shard.Data),
		Status:    "failed",
		StartedAt: startedAt,
	}
	if m.mixnet == nil {
		err := fmt.Errorf("%w: mixnet runtime is not initialized", ErrInvalidConfig)
		result.Error = err.Error()
		result.FinishedAt = time.Now().UTC()
		errs <- err
		return result
	}

	framePrefix, err := encodeDataFramePrefix(uploadID, shard.Index, totalShards, len(shard.Data), m.cfg.MaxFrameSize)
	if err != nil {
		result.Error = err.Error()
		result.FinishedAt = time.Now().UTC()
		errs <- err
		return result
	}
	if m.host != nil && len(target.Addrs) > 0 {
		m.host.Peerstore().AddAddrs(target.ID, target.Addrs, peerstore.TempAddrTTL)
	}
	timeout := m.mixnetStreamTimeout(mode)
	opCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if m.host != nil {
		_ = m.host.Connect(opCtx, target)
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		stream, openErr := m.mixnet.OpenStream(opCtx, target.ID)
		if openErr != nil {
			lastErr = openErr
			continue
		}
		sendErr := writeAll(stream, framePrefix)
		if sendErr == nil {
			sendErr = writeAll(stream, shard.Data)
		}
		if sendErr != nil {
			lastErr = sendErr
			_ = stream.Close()
			continue
		}
		if mode == SuccessModeAckOnPersist {
			ack, ackErr := readAckFromStream(stream, m.cfg.MaxFrameSize)
			if ackErr != nil {
				lastErr = ackErr
				_ = stream.Close()
				continue
			}
			if !ack.Accepted {
				lastErr = fmt.Errorf("receiver rejected shard %d: %s", shard.Index, ack.Message)
				_ = stream.Close()
				continue
			}
			result.Acked = true
		}
		_ = stream.Close()
		result.Status = "success"
		result.FinishedAt = time.Now().UTC()
		return result
	}

	if lastErr == nil {
		lastErr = io.ErrUnexpectedEOF
	}
	result.Error = lastErr.Error()
	result.FinishedAt = time.Now().UTC()
	errs <- lastErr
	return result
}

func (m *Manager) mixnetStreamTimeout(mode SuccessMode) time.Duration {
	timeout := m.cfg.SendTimeout
	if mode == SuccessModeAckOnPersist {
		timeout += m.cfg.AckTimeout
	}
	if timeout <= 0 {
		return time.Minute
	}
	return timeout
}

func readAckFromStream(stream io.Reader, maxFrameSize int) (ackFrame, error) {
	framePayload, err := readWireFrame(stream, maxFrameSize)
	if err != nil {
		return ackFrame{}, err
	}
	if len(framePayload) == 0 || framePayload[0] != frameTypeAck {
		return ackFrame{}, fmt.Errorf("%w: expected ack frame", ErrProtocolViolation)
	}
	return decodeAckFrame(framePayload)
}

func writeAll(w io.Writer, payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	written := 0
	for written < len(payload) {
		n, err := w.Write(payload[written:])
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		written += n
	}
	return nil
}

func (m *Manager) resolvePeers(
	ctx context.Context,
	explicit []peer.AddrInfo,
	required int,
) ([]peer.AddrInfo, error) {
	if m.resolver == nil {
		return nil, ErrResolverUnavailable
	}
	peers, err := m.resolver.ResolvePeers(ctx, PeerResolveRequest{
		Required:   required,
		Explicit:   explicit,
		LocalPeer:  m.host.ID(),
		ProtocolID: m.cfg.ProtocolID,
	})
	if err != nil {
		return nil, err
	}
	if len(peers) != required {
		return nil, fmt.Errorf("%w: resolver returned %d peers, need %d", ErrInsufficientPeers, len(peers), required)
	}
	seen := make(map[peer.ID]struct{}, len(peers))
	for _, p := range peers {
		if _, ok := seen[p.ID]; ok {
			return nil, fmt.Errorf("%w: duplicate peer %s", ErrInvalidRequest, p.ID)
		}
		seen[p.ID] = struct{}{}
	}
	return peers, nil
}

func (m *Manager) createReceptors(ctx context.Context, peers []peer.AddrInfo) ([]*hub.Receptor, error) {
	receptors := make([]*hub.Receptor, 0, len(peers))
	for _, p := range peers {
		receptor, err := m.hub.CreateReceptor(ctx, p)
		if err != nil && receptor == nil {
			m.cleanupReceptors(receptors)
			return nil, err
		}
		if receptor != nil {
			receptors = append(receptors, receptor)
		}
	}
	if len(receptors) != len(peers) {
		m.cleanupReceptors(receptors)
		return nil, fmt.Errorf("%w: receptor count mismatch", ErrInvalidRequest)
	}
	return receptors, nil
}

func (m *Manager) cleanupReceptors(receptors []*hub.Receptor) {
	for _, receptor := range receptors {
		if receptor == nil {
			continue
		}
		_ = m.hub.RemoveReceptor(receptor.ID())
	}
}

func (m *Manager) sendWithReconnect(ctx context.Context, receptor *hub.Receptor, parts ...[]byte) error {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		var sendErr error
		for _, part := range parts {
			if len(part) == 0 {
				continue
			}
			sendCtx, cancel := context.WithTimeout(ctx, m.cfg.SendTimeout)
			_, err := receptor.Send(sendCtx, part)
			cancel()
			if err != nil {
				sendErr = err
				break
			}
		}
		if sendErr == nil {
			return nil
		}
		lastErr = sendErr
		_ = m.hub.ResetStream(receptor.ID())
		openCtx, openCancel := context.WithTimeout(ctx, m.cfg.SendTimeout)
		openErr := m.hub.OpenStream(openCtx, receptor.ID())
		openCancel()
		if openErr != nil {
			lastErr = fmt.Errorf("send error: %v; open stream error: %w", sendErr, openErr)
			break
		}
	}
	return lastErr
}

func (m *Manager) waitAck(ctx context.Context, ackCh <-chan ackFrame) (ackFrame, error) {
	timer := time.NewTimer(m.cfg.AckTimeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ackFrame{}, ctx.Err()
	case <-timer.C:
		return ackFrame{}, ErrAckTimeout
	case ack := <-ackCh:
		return ack, nil
	}
}

func (m *Manager) registerWaiter(key ackKey, ch chan ackFrame) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ackWaiters[key] = ch
}

func (m *Manager) unregisterWaiter(key ackKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.ackWaiters, key)
}

func (m *Manager) runMetricsLoop() {
	for {
		select {
		case <-m.ctx.Done():
			return
		case _, ok := <-m.hub.Metrics():
			if !ok {
				return
			}
		}
	}
}

func (m *Manager) runEventLoop() {
	for {
		select {
		case <-m.ctx.Done():
			return
		case evt, ok := <-m.hub.Events():
			if !ok {
				return
			}
			switch evt.Kind {
			case hub.EventKindDataReceived:
				m.handleEventData(evt.StreamID, evt.Data)
			case hub.EventKindStreamClosed:
				m.clearStreamBuffer(evt.StreamID)
			}
		}
	}
}

func (m *Manager) handleEventData(streamID string, data []byte) {
	if streamID == "" || len(data) == 0 {
		return
	}
	m.mu.Lock()
	buffer := append(m.buffers[streamID], data...)
	frames, remaining, err := decodePayloadFrames(buffer, m.cfg.MaxFrameSize)
	if err != nil {
		delete(m.buffers, streamID)
		m.mu.Unlock()
		return
	}
	m.buffers[streamID] = remaining
	waiters := make(map[ackKey]chan ackFrame, len(m.ackWaiters))
	for k, ch := range m.ackWaiters {
		waiters[k] = ch
	}
	m.mu.Unlock()

	for _, framePayload := range frames {
		if len(framePayload) == 0 || framePayload[0] != frameTypeAck {
			continue
		}
		ack, err := decodeAckFrame(framePayload)
		if err != nil {
			continue
		}
		key := ackKey{uploadID: ack.UploadID, shardIndex: ack.ShardIndex}
		if ch, ok := waiters[key]; ok {
			select {
			case ch <- ack:
			default:
			}
		}
	}
}

func (m *Manager) clearStreamBuffer(streamID string) {
	if streamID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.buffers, streamID)
}

func (m *Manager) maxConcurrency(shardCount int) int {
	if m.cfg.MaxConcurrency <= 0 || m.cfg.MaxConcurrency > shardCount {
		return shardCount
	}
	return m.cfg.MaxConcurrency
}

func (m *Manager) beginUpload(uploadID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.active[uploadID]; exists {
		return fmt.Errorf("%w: %s", ErrUploadInProgress, uploadID)
	}
	m.active[uploadID] = struct{}{}
	return nil
}

func (m *Manager) endUpload(uploadID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.active, uploadID)
}
