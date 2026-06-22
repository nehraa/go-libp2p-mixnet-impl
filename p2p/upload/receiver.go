package upload

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/routing"
	"github.com/libp2p/go-libp2p/p2p/hub"
)

// Receiver owns upload stream handling and shard persistence on inbound peers.
type Receiver struct {
	cfg Config

	host    host.Host
	routing routing.Routing
	mixnet  mixnetRuntime

	shardStore    ShardStore
	manifestStore ReceiverManifestStore

	mu         sync.Mutex
	registered bool
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// NewReceiver creates an upload receiver.
func NewReceiver(cfg Config) (*Receiver, error) {
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	r := &Receiver{
		cfg: normalized,
	}
	if normalized.ShardStore != nil {
		r.shardStore = normalized.ShardStore
	} else {
		r.shardStore = NewFileShardStore(normalized.ReceiverRoot, normalized.OverwriteShards)
	}
	if normalized.ReceiverManifestStore != nil {
		r.manifestStore = normalized.ReceiverManifestStore
	} else {
		r.manifestStore = NewFileReceiverManifestStore(normalized.ReceiverRoot)
	}
	return r, nil
}

// Register installs the upload stream handler on h.
func (r *Receiver) Register(ctx context.Context, h host.Host, rt routing.Routing) error {
	if h == nil {
		return fmt.Errorf("%w: host is required", ErrInvalidConfig)
	}
	if ctx == nil {
		ctx = context.Background()
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.registered {
		return fmt.Errorf("%w: receiver already registered", ErrInvalidConfig)
	}

	r.host = h
	r.routing = rt
	if r.cfg.HubConfig.TransportMode == hub.TransportModeMixnet {
		mixRuntime, err := createMixnetRuntime(h, rt, r.cfg.HubConfig)
		if err != nil {
			return err
		}
		r.mixnet = mixRuntime
		r.ctx, r.cancel = context.WithCancel(context.Background())
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.runMixnetAcceptLoop()
		}()
	} else {
		r.host.SetStreamHandler(r.cfg.ProtocolID, r.handleStream)
	}
	r.registered = true

	if r.cfg.AdvertiseReceiver && r.routing != nil {
		namespace := r.cfg.DiscoveryNamespace
		go r.advertise(context.WithoutCancel(ctx), namespace)
	}
	return nil
}

// Close unregisters the upload stream handler.
func (r *Receiver) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.registered || r.host == nil {
		return nil
	}
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()
	if r.mixnet != nil {
		if err := r.mixnet.Close(); err != nil {
			return err
		}
		r.mixnet = nil
	} else {
		r.host.RemoveStreamHandler(r.cfg.ProtocolID)
	}
	r.cancel = nil
	r.ctx = nil
	r.registered = false
	return nil
}

func (r *Receiver) advertise(ctx context.Context, namespace string) {
	if r.routing == nil {
		return
	}
	c, err := cidFromNamespace(namespace)
	if err != nil {
		return
	}
	provideCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_ = r.routing.Provide(provideCtx, c, true)
}

func (r *Receiver) handleStream(stream network.Stream) {
	defer stream.Close()

	for {
		_ = stream.SetReadDeadline(time.Now().Add(r.cfg.ReceiveTimeout))
		framePayload, err := readWireFrame(stream, r.cfg.MaxFrameSize)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return
			}
			_ = stream.Reset()
			return
		}
		if len(framePayload) == 0 {
			_ = stream.Reset()
			return
		}

		switch framePayload[0] {
		case frameTypeData:
			data, err := decodeDataFrame(framePayload)
			if err != nil {
				_ = stream.Reset()
				return
			}
			ack := r.persistAndAck(stream.Conn().RemotePeer().String(), data)
			ackBytes, ackErr := encodeAckFrame(ack)
			if ackErr != nil {
				_ = stream.Reset()
				return
			}
			_ = stream.SetWriteDeadline(time.Now().Add(r.cfg.SendTimeout))
			if _, err := stream.Write(ackBytes); err != nil {
				_ = stream.Reset()
				return
			}
		case frameTypeAck:
			// Receiver ignores inbound ack frames.
			continue
		default:
			_ = stream.Reset()
			return
		}
	}
}

func (r *Receiver) runMixnetAcceptLoop() {
	if r.mixnet == nil || r.ctx == nil {
		return
	}
	for {
		stream, err := r.mixnet.AcceptStream(r.ctx)
		if err != nil {
			if r.ctx.Err() != nil {
				return
			}
			continue
		}
		go r.handleMixnetStream(stream)
	}
}

func (r *Receiver) handleMixnetStream(stream mixnetStream) {
	defer stream.Close()
	for {
		framePayload, err := readWireFrame(stream, r.cfg.MaxFrameSize)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return
			}
			return
		}
		if len(framePayload) == 0 {
			return
		}
		switch framePayload[0] {
		case frameTypeData:
			data, decodeErr := decodeDataFrame(framePayload)
			if decodeErr != nil {
				return
			}
			ack := r.persistAndAck("", data)
			ackBytes, ackErr := encodeAckFrame(ack)
			if ackErr != nil {
				return
			}
			if err := writeAll(stream, ackBytes); err != nil {
				return
			}
		case frameTypeAck:
			continue
		default:
			return
		}
	}
}

func (r *Receiver) persistAndAck(senderPeerID string, frame dataFrame) ackFrame {
	ack := ackFrame{
		UploadID:   frame.UploadID,
		ShardIndex: frame.ShardIndex,
		Accepted:   false,
	}
	if frame.ShardCount <= 0 || frame.ShardIndex < 0 || frame.ShardIndex >= frame.ShardCount {
		ack.Message = "invalid shard metadata"
		return ack
	}
	if r.cfg.MaxShardCount > 0 && frame.ShardCount > r.cfg.MaxShardCount {
		ack.Message = fmt.Sprintf("shard count %d exceeds configured limit %d", frame.ShardCount, r.cfg.MaxShardCount)
		return ack
	}
	if r.cfg.MaxShardBytes > 0 && len(frame.Payload) > r.cfg.MaxShardBytes {
		ack.Message = fmt.Sprintf("shard size %d exceeds configured limit %d", len(frame.Payload), r.cfg.MaxShardBytes)
		return ack
	}

	writeCtx, cancel := context.WithTimeout(context.Background(), r.cfg.ReceiveTimeout)
	defer cancel()
	if r.cfg.ShardPolicy != nil {
		if err := r.cfg.ShardPolicy.ValidateShard(writeCtx, ShardValidationRequest{
			UploadID:     frame.UploadID,
			SenderPeerID: senderPeerID,
			ShardIndex:   frame.ShardIndex,
			TotalShards:  frame.ShardCount,
			Data:         frame.Payload,
		}); err != nil {
			ack.Message = err.Error()
			return ack
		}
	}

	writeRes, err := r.shardStore.WriteShard(writeCtx, ShardWriteRequest{
		UploadID:    frame.UploadID,
		ShardIndex:  frame.ShardIndex,
		TotalShards: frame.ShardCount,
		Data:        frame.Payload,
	})
	if err != nil {
		ack.Message = err.Error()
		return ack
	}

	manifestPath, err := r.manifestStore.SaveReceiverShard(writeCtx, ReceiverManifest{
		UploadID:   frame.UploadID,
		ProtocolID: string(r.cfg.ProtocolID),
		ShardCount: frame.ShardCount,
		Records: []ReceiverShardRecord{
			{
				ShardIndex:   frame.ShardIndex,
				TotalShards:  frame.ShardCount,
				Path:         writeRes.Path,
				Bytes:        writeRes.Bytes,
				SenderPeerID: senderPeerID,
				ReceivedAt:   time.Now().UTC(),
			},
		},
		UpdatedAt: time.Now().UTC(),
	})
	if err != nil {
		ack.Message = err.Error()
		return ack
	}

	ack.Accepted = true
	ack.Message = manifestPath
	return ack
}
