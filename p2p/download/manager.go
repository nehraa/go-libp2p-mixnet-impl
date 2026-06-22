package download

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/routing"
	"github.com/libp2p/go-libp2p/p2p/hub"
	"github.com/libp2p/go-libp2p/p2p/shardxfer"
)

type pendingKey struct {
	peerID     peer.ID
	requestID  string
	shardIndex int
}

type shardReceiver struct {
	uploadID   string
	requestID  string
	shardIndex int
	peerID     peer.ID
	descriptor ShardDescriptor
	finalPath  string
	tempPath   string

	mu        sync.Mutex
	file      *os.File
	hasher    hash.Hash
	bytes     int64
	done      chan struct{}
	doneOnce  sync.Once
	err       error
	completed bool
}

func newShardReceiver(
	uploadID string,
	requestID string,
	shardIndex int,
	peerID peer.ID,
	descriptor ShardDescriptor,
	finalPath string,
	tempPath string,
) (*shardReceiver, error) {
	file, err := os.OpenFile(tempPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &shardReceiver{
		uploadID:   uploadID,
		requestID:  requestID,
		shardIndex: shardIndex,
		peerID:     peerID,
		descriptor: descriptor,
		finalPath:  finalPath,
		tempPath:   tempPath,
		file:       file,
		hasher:     sha256.New(),
		done:       make(chan struct{}),
	}, nil
}

func (r *shardReceiver) handleChunk(frame shardChunkFrame) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.completed || r.err != nil {
		return
	}
	if frame.UploadID != r.uploadID || frame.RequestID != r.requestID || frame.ShardIndex != r.shardIndex {
		return
	}
	if int64(frame.Offset) != r.bytes {
		r.finishLocked(fmt.Errorf("%w: shard %d chunk offset mismatch expected=%d got=%d", ErrHolderUnavailable, r.shardIndex, r.bytes, frame.Offset))
		return
	}
	if len(frame.Data) == 0 {
		return
	}
	n, err := r.file.Write(frame.Data)
	if err != nil {
		r.finishLocked(fmt.Errorf("write shard %d chunk: %w", r.shardIndex, err))
		return
	}
	if n != len(frame.Data) {
		r.finishLocked(fmt.Errorf("short write shard %d chunk: %d/%d", r.shardIndex, n, len(frame.Data)))
		return
	}
	_, _ = r.hasher.Write(frame.Data)
	r.bytes += int64(n)
}

func (r *shardReceiver) handleEnd(frame shardEndFrame) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.completed || r.err != nil {
		return
	}
	if frame.UploadID != r.uploadID || frame.RequestID != r.requestID || frame.ShardIndex != r.shardIndex {
		return
	}
	if frame.TotalBytes != uint64(r.bytes) {
		r.finishLocked(fmt.Errorf("%w: shard %d total byte mismatch expected=%d got=%d", ErrHolderUnavailable, r.shardIndex, r.bytes, frame.TotalBytes))
		return
	}
	if r.descriptor.Size > 0 && r.bytes != r.descriptor.Size {
		r.finishLocked(fmt.Errorf("%w: shard %d size mismatch expected=%d got=%d", ErrShardIntegrity, r.shardIndex, r.descriptor.Size, r.bytes))
		return
	}
	actualDigest := r.hasher.Sum(nil)
	if !digestEqual(actualDigest, r.descriptor.Digest) {
		r.finishLocked(fmt.Errorf("%w: shard %d digest mismatch", ErrShardIntegrity, r.shardIndex))
		return
	}
	if err := r.file.Sync(); err != nil {
		r.finishLocked(fmt.Errorf("sync shard %d temp file: %w", r.shardIndex, err))
		return
	}
	if err := r.file.Close(); err != nil {
		r.file = nil
		r.finishLocked(fmt.Errorf("close shard %d temp file: %w", r.shardIndex, err))
		return
	}
	r.file = nil
	if err := os.Rename(r.tempPath, r.finalPath); err != nil {
		r.finishLocked(fmt.Errorf("rename shard %d temp file: %w", r.shardIndex, err))
		return
	}
	r.completed = true
	r.doneOnce.Do(func() { close(r.done) })
}

func (r *shardReceiver) fail(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.finishLocked(err)
}

func (r *shardReceiver) finishLocked(err error) {
	if r.err != nil || r.completed {
		return
	}
	r.err = err
	if r.file != nil {
		_ = r.file.Close()
		r.file = nil
	}
	_ = os.Remove(r.tempPath)
	r.doneOnce.Do(func() { close(r.done) })
}

func (r *shardReceiver) result() (path string, bytes int64, err error, completed bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.finalPath, r.bytes, r.err, r.completed
}

// Manager orchestrates requester-side parallel shard downloads.
type Manager struct {
	cfg       Config
	host      host.Host
	routing   routing.Routing
	mode      hub.TransportMode
	hub       *hub.Hub
	mixnet    mixnetRuntime
	streamOps streamReopener

	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	buffers  map[string][]byte
	pending  map[pendingKey]*shardReceiver
	active   map[string]struct{}
	requestN atomic.Uint64

	wg sync.WaitGroup
}

// NewManager creates a download manager for hub or mixnet transport mode.
func NewManager(h host.Host, r routing.Routing, cfg Config) (*Manager, error) {
	if h == nil {
		return nil, fmt.Errorf("%w: host is required", ErrInvalidConfig)
	}
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		cfg:     normalized,
		host:    h,
		routing: r,
		mode:    normalized.HubConfig.TransportMode,
		ctx:     ctx,
		cancel:  cancel,
		buffers: make(map[string][]byte),
		pending: make(map[pendingKey]*shardReceiver),
		active:  make(map[string]struct{}),
	}
	if m.mode == hub.TransportModeMixnet {
		mixRuntime, createErr := createMixnetRuntime(h, r, normalized.HubConfig)
		if createErr != nil {
			cancel()
			return nil, createErr
		}
		m.mixnet = mixRuntime
	} else {
		hb, createErr := hub.New(h, normalized.HubConfig)
		if createErr != nil {
			cancel()
			return nil, fmt.Errorf("create download hub: %w", createErr)
		}
		m.hub = hb
		m.streamOps = hb
		m.wg.Add(2)
		go func() {
			defer m.wg.Done()
			m.runEventLoop()
		}()
		go func() {
			defer m.wg.Done()
			m.runMetricsLoop()
		}()
	}
	return m, nil
}

// Close stops loops and closes the manager hub.
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

// Download fetches shards in parallel from explicit shard holders and reconstructs output.
func (m *Manager) Download(ctx context.Context, req DownloadRequest) (DownloadResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	startedAt := time.Now().UTC()

	normalizedUploadID, mode, descriptorMap, sourceMap, err := m.validateRequest(req)
	if err != nil {
		return DownloadResult{}, err
	}
	if err := m.beginDownload(normalizedUploadID); err != nil {
		return DownloadResult{}, err
	}
	defer m.endDownload(normalizedUploadID)
	log.Debug("download started", "upload_id", normalizedUploadID, "mode", mode, "sources", len(sourceMap))

	var receptors map[int]*hub.Receptor
	if m.mode != hub.TransportModeMixnet {
		receptors, err = m.createReceptors(ctx, sourceMap)
		if err != nil {
			return DownloadResult{}, err
		}
		defer m.cleanupReceptors(receptors)
	}

	downloadDir := filepath.Join(m.cfg.DownloadRoot, normalizedUploadID)
	shardDir := filepath.Join(downloadDir, "shards")
	tmpDir := filepath.Join(downloadDir, ".tmp")
	if err := os.MkdirAll(shardDir, 0o755); err != nil {
		return DownloadResult{}, fmt.Errorf("create shard dir: %w", err)
	}
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return DownloadResult{}, fmt.Errorf("create tmp dir: %w", err)
	}

	results := make([]ShardDownloadResult, 0, len(sourceMap))
	resultsMu := sync.Mutex{}
	sem := make(chan struct{}, m.maxConcurrency(len(sourceMap)))
	errCh := make(chan error, len(sourceMap))
	wg := sync.WaitGroup{}

	for shardIndex, source := range sourceMap {
		shardIndex := shardIndex
		source := source
		descriptor := descriptorMap[shardIndex]
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var shardResult ShardDownloadResult
			if m.mode == hub.TransportModeMixnet {
				shardResult = m.fetchShardWithRetriesMixnet(ctx, normalizedUploadID, source, descriptor, shardDir, tmpDir)
			} else {
				receptor := receptors[shardIndex]
				shardResult = m.fetchShardWithRetries(ctx, normalizedUploadID, source, receptor, descriptor, shardDir, tmpDir)
			}
			resultsMu.Lock()
			results = append(results, shardResult)
			resultsMu.Unlock()
			if shardResult.Status != "success" {
				errCh <- fmt.Errorf("shard %d download failed: %s", shardResult.Index, shardResult.Error)
			}
		}()
	}
	wg.Wait()
	close(errCh)

	sort.Slice(results, func(i, j int) bool {
		return results[i].Index < results[j].Index
	})

	var firstErr error
	for downloadErr := range errCh {
		if firstErr == nil {
			firstErr = downloadErr
		}
	}

	successShards := collectSuccessfulShards(results)
	missing, invalid := classifyShardOutcomes(results, req.SignedManifest.Manifest.TotalShards)
	outputPath := req.OutputPath
	if outputPath == "" {
		outputPath = filepath.Join(downloadDir, "reconstructed.bin")
	}
	reconstructErr := m.reconstructOutput(
		ctx,
		mode,
		req.Threshold,
		req.SignedManifest.Manifest.TotalShards,
		successShards,
		outputPath,
	)
	if reconstructErr != nil && firstErr == nil {
		firstErr = reconstructErr
	}
	if reconstructErr == nil {
		for i := range results {
			if results[i].Status == "success" {
				results[i].Reconstructed = true
			}
		}
	}

	finishedAt := time.Now().UTC()
	if firstErr != nil {
		log.Warn("download finished with errors", "upload_id", normalizedUploadID, "err", firstErr, "mode", mode)
	} else {
		log.Debug("download finished successfully", "upload_id", normalizedUploadID, "output_path", outputPath, "mode", mode)
	}
	return DownloadResult{
		UploadID:      normalizedUploadID,
		Mode:          mode,
		OutputPath:    outputPath,
		ShardResults:  results,
		MissingShards: missing,
		InvalidShards: invalid,
		StartedAt:     startedAt,
		FinishedAt:    finishedAt,
	}, firstErr
}

func (m *Manager) validateRequest(
	req DownloadRequest,
) (string, ReconstructionMode, map[int]ShardDescriptor, map[int]ShardSource, error) {
	uploadID, err := normalizeUploadID(req.UploadID)
	if err != nil {
		return "", "", nil, nil, err
	}
	mode, err := effectiveMode(req.Mode)
	if err != nil {
		return "", "", nil, nil, err
	}
	if err := VerifySignedManifest(req.SignedManifest); err != nil {
		return "", "", nil, nil, err
	}
	if req.SignedManifest.Manifest.UploadID != uploadID {
		return "", "", nil, nil, fmt.Errorf("%w: request upload id %q does not match manifest upload id %q", ErrInvalidRequest, uploadID, req.SignedManifest.Manifest.UploadID)
	}
	if len(req.Sources) == 0 {
		return "", "", nil, nil, fmt.Errorf("%w: at least one source is required", ErrInvalidRequest)
	}

	descriptorMap := descriptorByIndex(req.SignedManifest.Manifest)
	sourceMap := make(map[int]ShardSource, len(req.Sources))
	seenPeers := make(map[peer.ID]struct{}, len(req.Sources))
	for _, src := range req.Sources {
		if src.ShardIndex < 0 {
			return "", "", nil, nil, fmt.Errorf("%w: invalid shard index %d", ErrInvalidRequest, src.ShardIndex)
		}
		if src.Holder.ID == "" {
			return "", "", nil, nil, fmt.Errorf("%w: source peer id required for shard %d", ErrInvalidRequest, src.ShardIndex)
		}
		if _, exists := sourceMap[src.ShardIndex]; exists {
			return "", "", nil, nil, fmt.Errorf("%w: duplicate source for shard %d", ErrInvalidRequest, src.ShardIndex)
		}
		if _, exists := seenPeers[src.Holder.ID]; exists {
			return "", "", nil, nil, fmt.Errorf("%w: duplicate source peer %s", ErrInvalidRequest, src.Holder.ID)
		}
		seenPeers[src.Holder.ID] = struct{}{}

		descriptor, ok := descriptorMap[src.ShardIndex]
		if !ok {
			return "", "", nil, nil, fmt.Errorf("%w: source shard %d not present in manifest", ErrInvalidRequest, src.ShardIndex)
		}
		if descriptor.HolderPeerID != src.Holder.ID.String() {
			return "", "", nil, nil, fmt.Errorf(
				"%w: source peer %s does not match manifest holder %s for shard %d",
				ErrInvalidRequest,
				src.Holder.ID,
				descriptor.HolderPeerID,
				src.ShardIndex,
			)
		}
		sourceMap[src.ShardIndex] = src
	}

	switch mode {
	case ReconstructionModeStrict:
		for shardIndex := 0; shardIndex < req.SignedManifest.Manifest.TotalShards; shardIndex++ {
			if _, ok := sourceMap[shardIndex]; !ok {
				return "", "", nil, nil, fmt.Errorf("%w: strict mode requires source for shard %d", ErrInvalidRequest, shardIndex)
			}
		}
	case ReconstructionModeThreshold:
		threshold := req.Threshold
		if threshold <= 0 {
			return "", "", nil, nil, fmt.Errorf("%w: threshold mode requires threshold > 0", ErrInvalidRequest)
		}
		if threshold > req.SignedManifest.Manifest.TotalShards {
			return "", "", nil, nil, fmt.Errorf("%w: threshold %d exceeds total shards %d", ErrInvalidRequest, threshold, req.SignedManifest.Manifest.TotalShards)
		}
		if len(sourceMap) < threshold {
			return "", "", nil, nil, fmt.Errorf("%w: threshold mode needs at least %d sources", ErrInvalidRequest, threshold)
		}
	case ReconstructionModeBestEffort:
	}
	return uploadID, mode, descriptorMap, sourceMap, nil
}

func (m *Manager) fetchShardWithRetries(
	ctx context.Context,
	uploadID string,
	source ShardSource,
	receptor *hub.Receptor,
	descriptor ShardDescriptor,
	shardDir string,
	tmpDir string,
) ShardDownloadResult {
	result := ShardDownloadResult{
		Index:     source.ShardIndex,
		PeerID:    source.Holder.ID.String(),
		Status:    "failed",
		StartedAt: time.Now().UTC(),
	}

	totalAttempts := 1 + m.cfg.RetryCount
	for attempt := 1; attempt <= totalAttempts; attempt++ {
		requestID := m.nextRequestID(uploadID, source.ShardIndex, attempt)
		result.RequestID = requestID
		result.Attempts = attempt

		finalPath := filepath.Join(shardDir, formatShardFile(source.ShardIndex))
		tempPath := filepath.Join(tmpDir, fmt.Sprintf("%06d.%s.tmp", source.ShardIndex, requestID))
		receiver, err := newShardReceiver(uploadID, requestID, source.ShardIndex, source.Holder.ID, descriptor, finalPath, tempPath)
		if err != nil {
			result.Error = err.Error()
			result.Status = "failed"
			continue
		}
		key := pendingKey{
			peerID:     source.Holder.ID,
			requestID:  requestID,
			shardIndex: source.ShardIndex,
		}
		m.registerPending(key, receiver)

		sendErr := m.sendPullRequest(ctx, receptor, pullRequestFrame{
			UploadID:   uploadID,
			RequestID:  requestID,
			ShardIndex: source.ShardIndex,
		})
		if sendErr != nil {
			log.Warn("download failed to send pull request", "upload_id", uploadID, "shard", source.ShardIndex, "peer", source.Holder.ID, "attempt", attempt, "err", sendErr)
			m.unregisterPending(key)
			receiver.fail(sendErr)
		}

		waitCtx, waitCancel := context.WithTimeout(ctx, m.cfg.ReceiveTimeout)
		waitDone := false
		select {
		case <-waitCtx.Done():
			receiver.fail(ErrDownloadTimeout)
		case <-receiver.done:
			waitDone = true
		}
		waitCancel()
		if !waitDone {
			<-receiver.done
		}
		m.unregisterPending(key)

		path, bytes, recvErr, completed := receiver.result()
		if recvErr == nil && completed {
			result.Path = path
			result.Bytes = bytes
			result.HashValid = true
			result.Status = "success"
			result.FinishedAt = time.Now().UTC()
			log.Debug("download shard succeeded", "upload_id", uploadID, "shard", source.ShardIndex, "peer", source.Holder.ID, "bytes", bytes, "attempt", attempt)
			return result
		}

		if recvErr != nil {
			result.Error = recvErr.Error()
			switch {
			case recvErr == ErrDownloadTimeout:
				result.Status = "timeout"
			case isIntegrityErr(recvErr):
				result.Status = "integrity_failed"
			default:
				result.Status = "failed"
			}
		}

		if attempt < totalAttempts {
			_ = m.hub.ResetStream(receptor.ID())
			openCtx, openCancel := context.WithTimeout(ctx, m.cfg.SendTimeout)
			_ = m.hub.OpenStream(openCtx, receptor.ID())
			openCancel()
			time.Sleep(m.cfg.RetryBackoff)
		}
	}

	result.FinishedAt = time.Now().UTC()
	log.Warn("download shard failed", "upload_id", uploadID, "shard", source.ShardIndex, "peer", source.Holder.ID, "attempts", result.Attempts, "status", result.Status, "err", result.Error)
	return result
}

func (m *Manager) fetchShardWithRetriesMixnet(
	ctx context.Context,
	uploadID string,
	source ShardSource,
	descriptor ShardDescriptor,
	shardDir string,
	tmpDir string,
) ShardDownloadResult {
	result := ShardDownloadResult{
		Index:     source.ShardIndex,
		PeerID:    source.Holder.ID.String(),
		Status:    "failed",
		StartedAt: time.Now().UTC(),
	}
	if m.mixnet == nil {
		result.Error = "mixnet runtime is not initialized"
		result.FinishedAt = time.Now().UTC()
		return result
	}

	totalAttempts := 1 + m.cfg.RetryCount
	for attempt := 1; attempt <= totalAttempts; attempt++ {
		requestID := m.nextRequestID(uploadID, source.ShardIndex, attempt)
		result.RequestID = requestID
		result.Attempts = attempt

		finalPath := filepath.Join(shardDir, formatShardFile(source.ShardIndex))
		tempPath := filepath.Join(tmpDir, fmt.Sprintf("%06d.%s.tmp", source.ShardIndex, requestID))
		receiver, err := newShardReceiver(uploadID, requestID, source.ShardIndex, source.Holder.ID, descriptor, finalPath, tempPath)
		if err != nil {
			result.Error = err.Error()
			result.Status = "failed"
			continue
		}

		timeout := m.cfg.ReceiveTimeout + m.cfg.SendTimeout
		if timeout <= 0 {
			timeout = time.Minute
		}
		opCtx, cancel := context.WithTimeout(ctx, timeout)
		if len(source.Holder.Addrs) > 0 {
			m.host.Peerstore().AddAddrs(source.Holder.ID, source.Holder.Addrs, peerstore.TempAddrTTL)
		}
		_ = m.host.Connect(opCtx, source.Holder)
		stream, openErr := m.mixnet.OpenStream(opCtx, source.Holder.ID)
		if openErr != nil {
			cancel()
			result.Error = openErr.Error()
			result.Status = "failed"
			if attempt < totalAttempts {
				time.Sleep(m.cfg.RetryBackoff)
			}
			continue
		}

		sendErr := m.sendPullRequestMixnet(stream, pullRequestFrame{
			UploadID:   uploadID,
			RequestID:  requestID,
			ShardIndex: source.ShardIndex,
		})
		if sendErr != nil {
			_ = stream.Close()
			cancel()
			receiver.fail(sendErr)
		} else {
			readErr := m.consumeShardFrames(stream, receiver)
			_ = stream.Close()
			if readErr != nil {
				receiver.fail(readErr)
			}
		}
		cancel()

		path, bytes, recvErr, completed := receiver.result()
		if recvErr == nil && completed {
			result.Path = path
			result.Bytes = bytes
			result.HashValid = true
			result.Status = "success"
			result.FinishedAt = time.Now().UTC()
			return result
		}
		if recvErr != nil {
			result.Error = recvErr.Error()
			switch {
			case recvErr == ErrDownloadTimeout:
				result.Status = "timeout"
			case isIntegrityErr(recvErr):
				result.Status = "integrity_failed"
			default:
				result.Status = "failed"
			}
		}
		if attempt < totalAttempts {
			time.Sleep(m.cfg.RetryBackoff)
		}
	}

	result.FinishedAt = time.Now().UTC()
	return result
}

func (m *Manager) sendPullRequestMixnet(stream io.Writer, frame pullRequestFrame) error {
	payload, err := encodePullRequestFrame(frame)
	if err != nil {
		return err
	}
	raw, err := shardxfer.EncodeFrame(frameKindPullRequest, payload, m.cfg.MaxFrameSize)
	if err != nil {
		return err
	}
	return writeAll(stream, raw)
}

func (m *Manager) consumeShardFrames(stream io.Reader, receiver *shardReceiver) error {
	for {
		frame, err := shardxfer.ReadFrame(stream, m.cfg.MaxFrameSize)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				return ErrDownloadTimeout
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				path, _, recvErr, completed := receiver.result()
				if completed && recvErr == nil && path != "" {
					return nil
				}
				return ErrHolderUnavailable
			}
			return err
		}
		switch frame.Kind {
		case frameKindShardChunk:
			chunkFrame, decodeErr := decodeShardChunkFrame(frame.Payload)
			if decodeErr != nil {
				return decodeErr
			}
			receiver.handleChunk(chunkFrame)
		case frameKindShardEnd:
			endFrame, decodeErr := decodeShardEndFrame(frame.Payload)
			if decodeErr != nil {
				return decodeErr
			}
			receiver.handleEnd(endFrame)
		case frameKindError:
			errFrame, decodeErr := decodeErrorFrame(frame.Payload)
			if decodeErr != nil {
				return decodeErr
			}
			return fmt.Errorf("%w: %s", ErrHolderUnavailable, errFrame.Message)
		default:
			return fmt.Errorf("%w: unknown frame kind %d", ErrInvalidRequest, frame.Kind)
		}
		select {
		case <-receiver.done:
			return nil
		default:
		}
	}
}

func (m *Manager) sendPullRequest(ctx context.Context, sender frameSender, frame pullRequestFrame) error {
	payload, err := encodePullRequestFrame(frame)
	if err != nil {
		return err
	}
	raw, err := shardxfer.EncodeFrame(frameKindPullRequest, payload, m.cfg.MaxFrameSize)
	if err != nil {
		return err
	}
	return sendFrameWithReconnect(ctx, sender, m.streamOps, m.cfg.SendTimeout, raw)
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
				m.handleDataEvent(evt.StreamID, evt.PeerID, evt.Data)
			case hub.EventKindStreamClosed:
				m.clearStreamBuffer(evt.StreamID)
			}
		}
	}
}

func (m *Manager) handleDataEvent(streamID string, peerID peer.ID, chunk []byte) {
	if streamID == "" || peerID == "" || len(chunk) == 0 {
		return
	}

	m.mu.Lock()
	buffer := append(m.buffers[streamID], chunk...)
	frames, remaining, err := shardxfer.DecodeBuffer(buffer, m.cfg.MaxFrameSize)
	if err != nil {
		delete(m.buffers, streamID)
		m.mu.Unlock()
		log.Warn("download failed to decode inbound frame", "peer", peerID, "stream_id", streamID, "err", err)
		return
	}
	m.buffers[streamID] = remaining
	pending := make(map[pendingKey]*shardReceiver, len(m.pending))
	for k, v := range m.pending {
		pending[k] = v
	}
	m.mu.Unlock()

	for _, frame := range frames {
		switch frame.Kind {
		case frameKindShardChunk:
			chunkFrame, err := decodeShardChunkFrame(frame.Payload)
			if err != nil {
				continue
			}
			key := pendingKey{peerID: peerID, requestID: chunkFrame.RequestID, shardIndex: chunkFrame.ShardIndex}
			if receiver := pending[key]; receiver != nil {
				receiver.handleChunk(chunkFrame)
			}
		case frameKindShardEnd:
			endFrame, err := decodeShardEndFrame(frame.Payload)
			if err != nil {
				continue
			}
			key := pendingKey{peerID: peerID, requestID: endFrame.RequestID, shardIndex: endFrame.ShardIndex}
			if receiver := pending[key]; receiver != nil {
				receiver.handleEnd(endFrame)
			}
		case frameKindError:
			errFrame, err := decodeErrorFrame(frame.Payload)
			if err != nil {
				continue
			}
			key := pendingKey{peerID: peerID, requestID: errFrame.RequestID, shardIndex: errFrame.ShardIndex}
			if receiver := pending[key]; receiver != nil {
				receiver.fail(fmt.Errorf("%w: %s", ErrHolderUnavailable, errFrame.Message))
			}
		}
	}
}

func (m *Manager) clearStreamBuffer(streamID string) {
	if streamID == "" {
		return
	}
	m.mu.Lock()
	delete(m.buffers, streamID)
	m.mu.Unlock()
}

func (m *Manager) beginDownload(uploadID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.active[uploadID]; ok {
		return fmt.Errorf("%w: %s", ErrInvalidRequest, uploadID)
	}
	m.active[uploadID] = struct{}{}
	return nil
}

func (m *Manager) endDownload(uploadID string) {
	m.mu.Lock()
	delete(m.active, uploadID)
	m.mu.Unlock()
}

func (m *Manager) registerPending(key pendingKey, receiver *shardReceiver) {
	m.mu.Lock()
	m.pending[key] = receiver
	m.mu.Unlock()
}

func (m *Manager) unregisterPending(key pendingKey) {
	m.mu.Lock()
	delete(m.pending, key)
	m.mu.Unlock()
}

func (m *Manager) nextRequestID(uploadID string, shardIndex int, attempt int) string {
	seq := m.requestN.Add(1)
	return fmt.Sprintf("%s-%d-%d-%d", uploadID, shardIndex, attempt, seq)
}

func (m *Manager) createReceptors(
	ctx context.Context,
	sourceMap map[int]ShardSource,
) (map[int]*hub.Receptor, error) {
	receptors := make(map[int]*hub.Receptor, len(sourceMap))
	for shardIndex, source := range sourceMap {
		receptor, err := m.hub.CreateReceptor(ctx, source.Holder)
		if err != nil && receptor == nil {
			m.cleanupReceptors(receptors)
			return nil, err
		}
		if receptor == nil {
			m.cleanupReceptors(receptors)
			return nil, fmt.Errorf("%w: nil receptor for shard %d", ErrHolderUnavailable, shardIndex)
		}
		receptors[shardIndex] = receptor
	}
	return receptors, nil
}

func (m *Manager) cleanupReceptors(receptors map[int]*hub.Receptor) {
	for _, receptor := range receptors {
		if receptor == nil {
			continue
		}
		_ = m.hub.RemoveReceptor(receptor.ID())
	}
}

func (m *Manager) reconstructOutput(
	ctx context.Context,
	mode ReconstructionMode,
	threshold int,
	totalShards int,
	shards []DownloadedShard,
	outputPath string,
) error {
	if len(shards) == 0 {
		return fmt.Errorf("%w: no successful shards", ErrInvalidRequest)
	}
	sort.Slice(shards, func(i, j int) bool {
		return shards[i].Index < shards[j].Index
	})
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	out, err := os.OpenFile(outputPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open output file: %w", err)
	}
	defer out.Close()

	switch mode {
	case ReconstructionModeStrict:
		if len(shards) != totalShards {
			return fmt.Errorf("%w: strict reconstruction needs %d shards, got %d", ErrInvalidRequest, totalShards, len(shards))
		}
		for i := 0; i < totalShards; i++ {
			if shards[i].Index != i {
				return fmt.Errorf("%w: missing shard index %d", ErrInvalidRequest, i)
			}
		}
		return concatShardFiles(ctx, shards, out)
	case ReconstructionModeBestEffort:
		return concatShardFiles(ctx, shards, out)
	case ReconstructionModeThreshold:
		if threshold <= 0 {
			return fmt.Errorf("%w: threshold must be > 0", ErrInvalidRequest)
		}
		if len(shards) < threshold {
			return fmt.Errorf("%w: threshold reconstruction needs at least %d shards, got %d", ErrInvalidRequest, threshold, len(shards))
		}
		if m.cfg.Reconstructor == nil {
			return ErrThresholdUnavailable
		}
		return m.cfg.Reconstructor.Reconstruct(ctx, shards, threshold, totalShards, out)
	default:
		return fmt.Errorf("%w: unsupported reconstruction mode %q", ErrInvalidRequest, mode)
	}
}

func concatShardFiles(ctx context.Context, shards []DownloadedShard, out io.Writer) error {
	for _, shard := range shards {
		if err := contextErr(ctx); err != nil {
			return err
		}
		file, err := os.Open(shard.Path)
		if err != nil {
			return fmt.Errorf("open shard %d for reconstruction: %w", shard.Index, err)
		}
		_, copyErr := io.Copy(out, file)
		closeErr := file.Close()
		if copyErr != nil {
			return fmt.Errorf("copy shard %d: %w", shard.Index, copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close shard %d: %w", shard.Index, closeErr)
		}
	}
	return nil
}

func collectSuccessfulShards(results []ShardDownloadResult) []DownloadedShard {
	shards := make([]DownloadedShard, 0, len(results))
	for _, result := range results {
		if result.Status == "success" && result.HashValid && result.Path != "" {
			shards = append(shards, DownloadedShard{
				Index: result.Index,
				Path:  result.Path,
				Bytes: result.Bytes,
			})
		}
	}
	return shards
}

func classifyShardOutcomes(results []ShardDownloadResult, total int) ([]int, []int) {
	present := make(map[int]struct{}, len(results))
	invalid := make([]int, 0, len(results))
	for _, result := range results {
		present[result.Index] = struct{}{}
		if result.Status == "integrity_failed" {
			invalid = append(invalid, result.Index)
		}
	}
	missing := make([]int, 0, total)
	for i := 0; i < total; i++ {
		if _, ok := present[i]; !ok {
			missing = append(missing, i)
		}
	}
	sort.Ints(invalid)
	return missing, invalid
}

func digestEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func isIntegrityErr(err error) bool {
	return err != nil && (errors.Is(err, ErrShardIntegrity) || strings.Contains(err.Error(), ErrShardIntegrity.Error()))
}

func (m *Manager) maxConcurrency(shardCount int) int {
	if shardCount <= 0 {
		return 1
	}
	if m.cfg.MaxConcurrency <= 0 || m.cfg.MaxConcurrency > shardCount {
		return shardCount
	}
	return m.cfg.MaxConcurrency
}
