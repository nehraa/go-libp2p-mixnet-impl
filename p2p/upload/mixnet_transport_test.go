package upload

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/routing"
	mixnet "github.com/libp2p/go-libp2p/mixnet/core"
	"github.com/libp2p/go-libp2p/p2p/hub"
	mocknet "github.com/libp2p/go-libp2p/p2p/net/mock"
)

type scriptedMixnetStream struct {
	reader *bytes.Reader
	writes bytes.Buffer
	closed bool
}

func newScriptedMixnetStream(readPayload []byte) *scriptedMixnetStream {
	return &scriptedMixnetStream{reader: bytes.NewReader(readPayload)}
}

func (s *scriptedMixnetStream) Read(p []byte) (int, error) {
	return s.reader.Read(p)
}

func (s *scriptedMixnetStream) Write(p []byte) (int, error) {
	return s.writes.Write(p)
}

func (s *scriptedMixnetStream) Close() error {
	s.closed = true
	return nil
}

type scriptedMixnetRuntime struct {
	stream    mixnetStream
	openCalls int
}

func (r *scriptedMixnetRuntime) OpenStream(context.Context, peer.ID) (mixnetStream, error) {
	r.openCalls++
	return r.stream, nil
}

func (r *scriptedMixnetRuntime) AcceptStream(context.Context) (mixnetStream, error) {
	return nil, io.EOF
}

func (r *scriptedMixnetRuntime) Close() error {
	return nil
}

func TestNewManagerMixnetRequiresRouting(t *testing.T) {
	mn, err := mocknet.FullMeshConnected(1)
	if err != nil {
		t.Fatalf("create mocknet: %v", err)
	}
	defer mn.Close()
	h := mn.Host(mn.Peers()[0])

	_, err = NewManager(h, nil, Config{
		ManifestRoot: t.TempDir(),
		HubConfig: hub.Config{
			TransportMode: hub.TransportModeMixnet,
		},
	})
	if err == nil {
		t.Fatal("expected mixnet manager to fail without routing")
	}
}

func TestSendShardOverMixnetWritesShardAndReadsAck(t *testing.T) {
	ackRaw, err := encodeAckFrame(ackFrame{
		UploadID:   "upload-1",
		ShardIndex: 0,
		Accepted:   true,
		Message:    "ok",
	})
	if err != nil {
		t.Fatalf("encode ack frame: %v", err)
	}
	stream := newScriptedMixnetStream(ackRaw)
	manager := &Manager{
		cfg: Config{
			MaxFrameSize: 1024,
			SendTimeout:  time.Second,
			AckTimeout:   time.Second,
		},
		mixnet: &scriptedMixnetRuntime{stream: stream},
	}

	errCh := make(chan error, 1)
	result := manager.sendShardOverMixnet(
		context.Background(),
		"upload-1",
		SuccessModeAckOnPersist,
		ShardView{Index: 0, Start: 0, End: 5, Data: []byte("hello")},
		1,
		peer.AddrInfo{ID: peer.ID("peer-1")},
		errCh,
	)
	select {
	case sendErr := <-errCh:
		t.Fatalf("unexpected send error: %v", sendErr)
	default:
	}
	if result.Status != "success" {
		t.Fatalf("expected success status, got %s", result.Status)
	}
	if !result.Acked {
		t.Fatal("expected shard to be acked")
	}

	expectedRaw, err := encodeDataFrame(dataFrame{
		UploadID:   "upload-1",
		ShardIndex: 0,
		ShardCount: 1,
		Payload:    []byte("hello"),
	})
	if err != nil {
		t.Fatalf("encode data frame: %v", err)
	}
	if !bytes.Equal(stream.writes.Bytes(), expectedRaw) {
		t.Fatalf("unexpected wire bytes: got %x want %x", stream.writes.Bytes(), expectedRaw)
	}
}

func TestManagerUploadUsesMixnetTransportWhenConfigured(t *testing.T) {
	mn, err := mocknet.FullMeshConnected(2)
	if err != nil {
		t.Fatalf("create mocknet: %v", err)
	}
	defer mn.Close()
	peers := mn.Peers()
	h := mn.Host(peers[0])
	target := peer.AddrInfo{
		ID:    peers[1],
		Addrs: mn.Host(peers[1]).Addrs(),
	}

	originalFactory := newMixnetRuntimeFactory
	t.Cleanup(func() {
		newMixnetRuntimeFactory = originalFactory
	})
	newMixnetRuntimeFactory = func(_ *mixnet.MixnetConfig, _ host.Host, _ routing.Routing) (mixnetRuntime, error) {
		ackRaw, ackErr := encodeAckFrame(ackFrame{
			UploadID:   "upload-mix",
			ShardIndex: 0,
			Accepted:   true,
			Message:    "ok",
		})
		if ackErr != nil {
			return nil, ackErr
		}
		return &scriptedMixnetRuntime{
			stream: newScriptedMixnetStream(ackRaw),
		}, nil
	}

	manager, err := NewManager(h, &staticRouting{}, Config{
		ManifestRoot: t.TempDir(),
		Resolver: resolverStub{
			peers: []peer.AddrInfo{target},
		},
		HubConfig: hub.Config{
			TransportMode: hub.TransportModeMixnet,
		},
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer manager.Close()

	result, err := manager.Upload(context.Background(), UploadRequest{
		UploadID:           "upload-mix",
		Buffer:             []byte("hello"),
		Delimiter:          []byte("|"),
		ExpectedShardCount: 1,
		SuccessMode:        SuccessModeAckOnPersist,
	})
	if err != nil {
		t.Fatalf("upload failed: %v", err)
	}
	if len(result.ShardResults) != 1 {
		t.Fatalf("expected one shard result, got %d", len(result.ShardResults))
	}
	if result.ShardResults[0].Status != "success" || !result.ShardResults[0].Acked {
		t.Fatalf("unexpected shard result: %+v", result.ShardResults[0])
	}
}
