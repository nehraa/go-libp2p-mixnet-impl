package download

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/hub"
	mocknet "github.com/libp2p/go-libp2p/p2p/net/mock"
	"github.com/libp2p/go-libp2p/p2p/shardxfer"
)

func TestNewManagerMixnetRequiresRouting(t *testing.T) {
	mn, err := mocknet.FullMeshConnected(1)
	if err != nil {
		t.Fatalf("create mocknet: %v", err)
	}
	defer mn.Close()
	h := mn.Host(mn.Peers()[0])

	_, err = NewManager(h, nil, Config{
		DownloadRoot: t.TempDir(),
		HubConfig: hub.Config{
			TransportMode: hub.TransportModeMixnet,
		},
	})
	if err == nil {
		t.Fatal("expected mixnet manager to fail without routing")
	}
}

func TestNewHolderServiceMixnetRequiresRouting(t *testing.T) {
	mn, err := mocknet.FullMeshConnected(1)
	if err != nil {
		t.Fatalf("create mocknet: %v", err)
	}
	defer mn.Close()
	h := mn.Host(mn.Peers()[0])

	_, err = NewHolderService(h, nil, Config{
		HolderRoot: t.TempDir(),
		HubConfig: hub.Config{
			TransportMode: hub.TransportModeMixnet,
		},
	})
	if err == nil {
		t.Fatal("expected mixnet holder service to fail without routing")
	}
}

func TestSendPullRequestMixnetWritesWireFrame(t *testing.T) {
	manager := &Manager{
		cfg: Config{
			MaxFrameSize: 1024,
		},
	}
	stream := &bytes.Buffer{}
	err := manager.sendPullRequestMixnet(stream, pullRequestFrame{
		UploadID:   "upload-1",
		RequestID:  "req-1",
		ShardIndex: 0,
	})
	if err != nil {
		t.Fatalf("send pull request mixnet: %v", err)
	}
	frame, err := shardxfer.ReadFrame(bytes.NewReader(stream.Bytes()), 1024)
	if err != nil {
		t.Fatalf("read encoded frame: %v", err)
	}
	if frame.Kind != frameKindPullRequest {
		t.Fatalf("unexpected frame kind %d", frame.Kind)
	}
	req, err := decodePullRequestFrame(frame.Payload)
	if err != nil {
		t.Fatalf("decode pull request frame: %v", err)
	}
	if req.RequestID != "req-1" || req.UploadID != "upload-1" || req.ShardIndex != 0 {
		t.Fatalf("unexpected decoded pull request: %+v", req)
	}
}

func TestConsumeShardFramesCompletesReceiver(t *testing.T) {
	const (
		uploadID  = "upload-1"
		requestID = "req-1"
		shardIdx  = 0
	)
	payload := []byte("hello")
	chunkPayload, err := encodeShardChunkFrame(shardChunkFrame{
		UploadID:   uploadID,
		RequestID:  requestID,
		ShardIndex: shardIdx,
		Offset:     0,
		Data:       payload,
	})
	if err != nil {
		t.Fatalf("encode shard chunk: %v", err)
	}
	endPayload, err := encodeShardEndFrame(shardEndFrame{
		UploadID:   uploadID,
		RequestID:  requestID,
		ShardIndex: shardIdx,
		TotalBytes: uint64(len(payload)),
	})
	if err != nil {
		t.Fatalf("encode shard end: %v", err)
	}
	chunkFrame, err := shardxfer.EncodeFrame(frameKindShardChunk, chunkPayload, 1024)
	if err != nil {
		t.Fatalf("encode chunk frame: %v", err)
	}
	endFrame, err := shardxfer.EncodeFrame(frameKindShardEnd, endPayload, 1024)
	if err != nil {
		t.Fatalf("encode end frame: %v", err)
	}
	stream := bytes.NewReader(append(chunkFrame, endFrame...))

	dir := t.TempDir()
	finalPath := filepath.Join(dir, "000000.part")
	tempPath := filepath.Join(dir, "000000.tmp")
	receiver, err := newShardReceiver(
		uploadID,
		requestID,
		shardIdx,
		peer.ID("holder-1"),
		ShardDescriptor{
			Index:        shardIdx,
			HolderPeerID: "holder-1",
			Size:         int64(len(payload)),
			DigestAlgo:   digestAlgoSHA256,
			Digest:       HashShard(payload),
		},
		finalPath,
		tempPath,
	)
	if err != nil {
		t.Fatalf("new shard receiver: %v", err)
	}

	manager := &Manager{cfg: Config{MaxFrameSize: 1024}}
	if err := manager.consumeShardFrames(stream, receiver); err != nil {
		t.Fatalf("consume shard frames: %v", err)
	}
	select {
	case <-receiver.done:
	case <-time.After(time.Second):
		t.Fatal("receiver did not finish")
	}
	path, bytesWritten, recvErr, completed := receiver.result()
	if recvErr != nil {
		t.Fatalf("receiver error: %v", recvErr)
	}
	if !completed {
		t.Fatal("expected receiver to complete")
	}
	if path != finalPath {
		t.Fatalf("unexpected final path: got %s want %s", path, finalPath)
	}
	if bytesWritten != int64(len(payload)) {
		t.Fatalf("unexpected byte count: got %d want %d", bytesWritten, len(payload))
	}
	raw, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatalf("read final shard: %v", err)
	}
	if !bytes.Equal(raw, payload) {
		t.Fatalf("unexpected final shard bytes: got %q want %q", raw, payload)
	}
}

func TestHolderAllowRequesterMixnetNoop(t *testing.T) {
	service := &HolderService{
		mode: hub.TransportModeMixnet,
	}
	err := service.AllowRequester(context.Background(), peer.AddrInfo{ID: peer.ID("peer-1")})
	if err != nil {
		t.Fatalf("allow requester should be noop in mixnet mode: %v", err)
	}
}
