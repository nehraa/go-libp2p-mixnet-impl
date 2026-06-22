package download

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/routing"
	"github.com/libp2p/go-libp2p/p2p/hub"
	"github.com/libp2p/go-libp2p/p2p/shardxfer"
)

// HolderService serves shard download requests from allowed requester peers.
type HolderService struct {
	cfg       Config
	host      host.Host
	routing   routing.Routing
	mode      hub.TransportMode
	hub       *hub.Hub
	mixnet    mixnetRuntime
	streamOps streamReopener
	provider  ShardProvider

	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	buffers map[string][]byte
	allowed map[peer.ID]*hub.Receptor
	wg      sync.WaitGroup
}

// NewHolderService creates a holder-side service bound to one host.
func NewHolderService(h host.Host, r routing.Routing, cfg Config) (*HolderService, error) {
	if h == nil {
		return nil, fmt.Errorf("%w: host is required", ErrInvalidConfig)
	}
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}

	provider := normalized.ShardProvider
	if provider == nil {
		provider = NewFileShardProvider(normalized.HolderRoot)
	}
	ctx, cancel := context.WithCancel(context.Background())
	service := &HolderService{
		cfg:      normalized,
		host:     h,
		routing:  r,
		mode:     normalized.HubConfig.TransportMode,
		provider: provider,
		ctx:      ctx,
		cancel:   cancel,
		buffers:  make(map[string][]byte),
		allowed:  make(map[peer.ID]*hub.Receptor),
	}
	if service.mode == hub.TransportModeMixnet {
		mixRuntime, createErr := createMixnetRuntime(h, r, normalized.HubConfig)
		if createErr != nil {
			cancel()
			return nil, createErr
		}
		service.mixnet = mixRuntime
		service.wg.Add(1)
		go func() {
			defer service.wg.Done()
			service.runMixnetAcceptLoop()
		}()
	} else {
		hb, createErr := hub.New(h, normalized.HubConfig)
		if createErr != nil {
			cancel()
			return nil, fmt.Errorf("create holder hub: %w", createErr)
		}
		service.hub = hb
		service.streamOps = hb
		service.wg.Add(2)
		go func() {
			defer service.wg.Done()
			service.runEventLoop()
		}()
		go func() {
			defer service.wg.Done()
			service.runMetricsLoop()
		}()
	}

	return service, nil
}

// Close stops holder loops and closes the internal hub.
func (s *HolderService) Close() error {
	s.cancel()
	s.wg.Wait()
	if s.hub != nil {
		return s.hub.Close()
	}
	if s.mixnet != nil {
		return s.mixnet.Close()
	}
	return nil
}

// AllowRequester pre-binds a requester peer so inbound hub streams are accepted.
func (s *HolderService) AllowRequester(ctx context.Context, requester peer.AddrInfo) error {
	if s.mode == hub.TransportModeMixnet {
		// Mixnet request handling is stream-based and does not require
		// pre-binding requesters to hub receptors.
		return nil
	}
	if requester.ID == "" {
		return fmt.Errorf("%w: requester peer id is required", ErrInvalidRequest)
	}
	if requester.ID == s.host.ID() {
		return fmt.Errorf("%w: requester cannot be local host", ErrInvalidRequest)
	}

	s.mu.Lock()
	_, exists := s.allowed[requester.ID]
	s.mu.Unlock()
	if exists {
		return nil
	}

	receptor, err := s.hub.CreateReceptor(ctx, requester)
	if err != nil && receptor == nil {
		return err
	}
	if receptor == nil {
		return fmt.Errorf("%w: holder receptor creation returned nil", ErrHolderUnavailable)
	}

	s.mu.Lock()
	s.allowed[requester.ID] = receptor
	s.mu.Unlock()
	if err != nil {
		log.Warn("holder requester bound with initial stream error", "requester", requester.ID, "err", err)
	} else {
		log.Debug("holder requester bound", "requester", requester.ID)
	}
	return nil
}

func (s *HolderService) runMetricsLoop() {
	if s.hub == nil {
		return
	}
	for {
		select {
		case <-s.ctx.Done():
			return
		case _, ok := <-s.hub.Metrics():
			if !ok {
				return
			}
		}
	}
}

func (s *HolderService) runEventLoop() {
	if s.hub == nil {
		return
	}
	for {
		select {
		case <-s.ctx.Done():
			return
		case evt, ok := <-s.hub.Events():
			if !ok {
				return
			}
			switch evt.Kind {
			case hub.EventKindDataReceived:
				s.handleDataEvent(evt.StreamID, evt.PeerID, evt.Data)
			case hub.EventKindStreamClosed:
				s.clearStreamBuffer(evt.StreamID)
			}
		}
	}
}

func (s *HolderService) runMixnetAcceptLoop() {
	if s.mixnet == nil {
		return
	}
	for {
		stream, err := s.mixnet.AcceptStream(s.ctx)
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			continue
		}
		go s.handleMixnetStream(stream)
	}
}

func (s *HolderService) handleMixnetStream(stream mixnetStream) {
	defer stream.Close()
	for {
		frame, err := shardxfer.ReadFrame(stream, s.cfg.MaxFrameSize)
		if err != nil {
			return
		}
		if frame.Kind != frameKindPullRequest {
			continue
		}
		req, decodeErr := decodePullRequestFrame(frame.Payload)
		if decodeErr != nil {
			return
		}
		s.servePullRequestMixnet(stream, req)
	}
}

func (s *HolderService) handleDataEvent(streamID string, peerID peer.ID, chunk []byte) {
	if streamID == "" || peerID == "" || len(chunk) == 0 {
		return
	}

	s.mu.Lock()
	buffer := append(s.buffers[streamID], chunk...)
	frames, remaining, err := shardxfer.DecodeBuffer(buffer, s.cfg.MaxFrameSize)
	if err != nil {
		delete(s.buffers, streamID)
		receptor := s.allowed[peerID]
		s.mu.Unlock()
		log.Warn("holder failed to decode inbound frame", "peer", peerID, "stream_id", streamID, "err", err)
		if receptor != nil {
			_ = s.hub.ResetStream(receptor.ID())
		}
		return
	}
	s.buffers[streamID] = remaining
	receptor := s.allowed[peerID]
	s.mu.Unlock()
	if receptor == nil {
		return
	}

	for _, frame := range frames {
		if frame.Kind != frameKindPullRequest {
			continue
		}
		req, err := decodePullRequestFrame(frame.Payload)
		if err != nil {
			log.Warn("holder received invalid pull request frame", "peer", peerID, "err", err)
			continue
		}
		go s.servePullRequest(peerID, receptor, req)
	}
}

func (s *HolderService) clearStreamBuffer(streamID string) {
	if streamID == "" {
		return
	}
	s.mu.Lock()
	delete(s.buffers, streamID)
	s.mu.Unlock()
}

func (s *HolderService) servePullRequest(peerID peer.ID, receptor frameSender, req pullRequestFrame) {
	log.Debug("holder received shard request", "peer", peerID, "upload_id", req.UploadID, "shard", req.ShardIndex, "request_id", req.RequestID)
	if req.ShardIndex < 0 {
		_ = s.sendErrorFrame(context.Background(), receptor, req.UploadID, req.RequestID, req.ShardIndex, "invalid shard index")
		return
	}

	readCtx, readCancel := context.WithTimeout(s.ctx, s.cfg.ReceiveTimeout)
	defer readCancel()
	result, err := s.provider.OpenShard(readCtx, req.UploadID, req.ShardIndex)
	if err != nil {
		log.Warn("holder failed to open shard", "peer", peerID, "upload_id", req.UploadID, "shard", req.ShardIndex, "err", err)
		_ = s.sendErrorFrame(context.Background(), receptor, req.UploadID, req.RequestID, req.ShardIndex, err.Error())
		return
	}
	defer result.Reader.Close()

	offset := uint64(0)
	buf := make([]byte, s.cfg.ChunkSize)
	for {
		n, readErr := result.Reader.Read(buf)
		if n > 0 {
			frame, err := encodeShardChunkFrame(shardChunkFrame{
				UploadID:   req.UploadID,
				RequestID:  req.RequestID,
				ShardIndex: req.ShardIndex,
				Offset:     offset,
				Data:       buf[:n],
			})
			if err != nil {
				_ = s.sendErrorFrame(context.Background(), receptor, req.UploadID, req.RequestID, req.ShardIndex, err.Error())
				return
			}
			if err := s.sendFrame(context.Background(), receptor, frameKindShardChunk, frame); err != nil {
				log.Warn("holder failed to send shard chunk", "peer", peerID, "upload_id", req.UploadID, "shard", req.ShardIndex, "err", err)
				return
			}
			offset += uint64(n)
		}

		if readErr == nil {
			continue
		}
		if readErr != io.EOF {
			log.Warn("holder shard read failed", "peer", peerID, "upload_id", req.UploadID, "shard", req.ShardIndex, "err", readErr)
			_ = s.sendErrorFrame(context.Background(), receptor, req.UploadID, req.RequestID, req.ShardIndex, readErr.Error())
			return
		}
		break
	}

	endPayload, err := encodeShardEndFrame(shardEndFrame{
		UploadID:   req.UploadID,
		RequestID:  req.RequestID,
		ShardIndex: req.ShardIndex,
		TotalBytes: offset,
	})
	if err != nil {
		_ = s.sendErrorFrame(context.Background(), receptor, req.UploadID, req.RequestID, req.ShardIndex, err.Error())
		return
	}
	if err := s.sendFrame(context.Background(), receptor, frameKindShardEnd, endPayload); err != nil {
		log.Warn("holder failed to send shard end frame", "peer", peerID, "upload_id", req.UploadID, "shard", req.ShardIndex, "err", err)
		return
	}
	log.Debug("holder finished shard request", "peer", peerID, "upload_id", req.UploadID, "shard", req.ShardIndex, "bytes", offset, "request_id", req.RequestID)
}

func (s *HolderService) sendErrorFrame(
	ctx context.Context,
	receptor frameSender,
	uploadID string,
	requestID string,
	shardIndex int,
	message string,
) error {
	payload, err := encodeErrorFrame(errorFrame{
		UploadID:   uploadID,
		RequestID:  requestID,
		ShardIndex: shardIndex,
		Message:    message,
	})
	if err != nil {
		return err
	}
	return s.sendFrame(ctx, receptor, frameKindError, payload)
}

func (s *HolderService) sendFrame(ctx context.Context, receptor frameSender, kind byte, payload []byte) error {
	raw, err := shardxfer.EncodeFrame(kind, payload, s.cfg.MaxFrameSize)
	if err != nil {
		return err
	}
	return sendFrameWithReconnect(ctx, receptor, s.streamOps, s.cfg.SendTimeout, raw)
}

func (s *HolderService) sendFrameMixnet(stream io.Writer, kind byte, payload []byte) error {
	raw, err := shardxfer.EncodeFrame(kind, payload, s.cfg.MaxFrameSize)
	if err != nil {
		return err
	}
	return writeAll(stream, raw)
}

func (s *HolderService) servePullRequestMixnet(stream io.Writer, req pullRequestFrame) {
	if req.ShardIndex < 0 {
		_ = s.sendErrorFrameMixnet(stream, req.UploadID, req.RequestID, req.ShardIndex, "invalid shard index")
		return
	}
	readCtx, readCancel := context.WithTimeout(s.ctx, s.cfg.ReceiveTimeout)
	defer readCancel()
	result, err := s.provider.OpenShard(readCtx, req.UploadID, req.ShardIndex)
	if err != nil {
		_ = s.sendErrorFrameMixnet(stream, req.UploadID, req.RequestID, req.ShardIndex, err.Error())
		return
	}
	defer result.Reader.Close()

	offset := uint64(0)
	buf := make([]byte, s.cfg.ChunkSize)
	for {
		n, readErr := result.Reader.Read(buf)
		if n > 0 {
			frame, encodeErr := encodeShardChunkFrame(shardChunkFrame{
				UploadID:   req.UploadID,
				RequestID:  req.RequestID,
				ShardIndex: req.ShardIndex,
				Offset:     offset,
				Data:       buf[:n],
			})
			if encodeErr != nil {
				_ = s.sendErrorFrameMixnet(stream, req.UploadID, req.RequestID, req.ShardIndex, encodeErr.Error())
				return
			}
			if sendErr := s.sendFrameMixnet(stream, frameKindShardChunk, frame); sendErr != nil {
				return
			}
			offset += uint64(n)
		}
		if readErr == nil {
			continue
		}
		if readErr != io.EOF {
			_ = s.sendErrorFrameMixnet(stream, req.UploadID, req.RequestID, req.ShardIndex, readErr.Error())
			return
		}
		break
	}
	endPayload, err := encodeShardEndFrame(shardEndFrame{
		UploadID:   req.UploadID,
		RequestID:  req.RequestID,
		ShardIndex: req.ShardIndex,
		TotalBytes: offset,
	})
	if err != nil {
		_ = s.sendErrorFrameMixnet(stream, req.UploadID, req.RequestID, req.ShardIndex, err.Error())
		return
	}
	_ = s.sendFrameMixnet(stream, frameKindShardEnd, endPayload)
}

func (s *HolderService) sendErrorFrameMixnet(
	stream io.Writer,
	uploadID string,
	requestID string,
	shardIndex int,
	message string,
) error {
	payload, err := encodeErrorFrame(errorFrame{
		UploadID:   uploadID,
		RequestID:  requestID,
		ShardIndex: shardIndex,
		Message:    message,
	})
	if err != nil {
		return err
	}
	return s.sendFrameMixnet(stream, frameKindError, payload)
}
