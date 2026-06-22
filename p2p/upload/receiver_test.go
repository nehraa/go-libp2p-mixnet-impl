package upload

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	routingcore "github.com/libp2p/go-libp2p/core/routing"
	"github.com/libp2p/go-libp2p/p2p/hub"
	mocknet "github.com/libp2p/go-libp2p/p2p/net/mock"
)

func TestReceiverRegisterAllowsNilContext(t *testing.T) {
	mn, err := mocknet.FullMeshConnected(1)
	if err != nil {
		t.Fatalf("create mocknet: %v", err)
	}
	defer mn.Close()

	peerIDs := mn.Peers()
	h := mn.Host(peerIDs[0])

	receiver, err := NewReceiver(Config{})
	if err != nil {
		t.Fatalf("new receiver: %v", err)
	}
	defer receiver.Close()

	if err := receiver.Register(nil, h, nil); err != nil {
		t.Fatalf("register receiver with nil context: %v", err)
	}
}

func TestReceiverRegisterMixnetRequiresRouting(t *testing.T) {
	mn, err := mocknet.FullMeshConnected(1)
	if err != nil {
		t.Fatalf("create mocknet: %v", err)
	}
	defer mn.Close()
	h := mn.Host(mn.Peers()[0])

	receiver, err := NewReceiver(Config{
		HubConfig: hub.Config{
			TransportMode: hub.TransportModeMixnet,
		},
	})
	if err != nil {
		t.Fatalf("new receiver: %v", err)
	}
	defer receiver.Close()

	if err := receiver.Register(context.Background(), h, nil); err == nil {
		t.Fatal("expected mixnet receiver registration to fail without routing")
	}
}

func TestReceiverAdvertiseCallsProvide(t *testing.T) {
	route := &stubRouting{}
	receiver := &Receiver{
		routing: route,
	}

	receiver.advertise(context.Background(), "/upload/advertise/test")
	if !route.provided {
		t.Fatal("expected advertise to call routing provider")
	}
}

func TestReceiverAdvertiseIgnoresNamespaceEncodingError(t *testing.T) {
	originalEncode := encodeMultihash
	defer func() {
		encodeMultihash = originalEncode
	}()
	encodeMultihash = func([]byte, uint64) ([]byte, error) {
		return nil, errors.New("encode failed")
	}

	route := &stubRouting{}
	receiver := &Receiver{routing: route}
	receiver.advertise(context.Background(), "/upload/advertise/test")
	if route.provided {
		t.Fatal("expected advertise to stop on namespace encoding error")
	}
}

func TestReceiverPersistAndAckRejectsShardOverConfiguredMaxBytes(t *testing.T) {
	shardStore := &stubShardStore{}
	manifestStore := &stubManifestStore{}

	receiver, err := NewReceiver(Config{
		MaxShardBytes:         3,
		ShardStore:            shardStore,
		ReceiverManifestStore: manifestStore,
	})
	if err != nil {
		t.Fatalf("new receiver: %v", err)
	}

	ack := receiver.persistAndAck("peer-a", dataFrame{
		UploadID:   "upload-limit",
		ShardIndex: 0,
		ShardCount: 1,
		Payload:    []byte("1234"),
	})
	if ack.Accepted {
		t.Fatal("expected oversized shard to be rejected")
	}
	if !strings.Contains(ack.Message, "exceeds configured limit") {
		t.Fatalf("unexpected ack message: %q", ack.Message)
	}
	if shardStore.called {
		t.Fatal("shard store should not be called for rejected shard")
	}
	if manifestStore.called {
		t.Fatal("manifest store should not be called for rejected shard")
	}
}

func TestReceiverPersistAndAckRejectsShardWhenPolicyFails(t *testing.T) {
	shardStore := &stubShardStore{}
	manifestStore := &stubManifestStore{}
	policy := &stubShardPolicy{err: errors.New("policy blocked shard")}

	receiver, err := NewReceiver(Config{
		MaxShardBytes:         1024,
		ShardStore:            shardStore,
		ReceiverManifestStore: manifestStore,
		ShardPolicy:           policy,
	})
	if err != nil {
		t.Fatalf("new receiver: %v", err)
	}

	ack := receiver.persistAndAck("peer-b", dataFrame{
		UploadID:   "upload-policy",
		ShardIndex: 0,
		ShardCount: 1,
		Payload:    []byte("ok"),
	})
	if ack.Accepted {
		t.Fatal("expected policy-rejected shard to be rejected")
	}
	if ack.Message != "policy blocked shard" {
		t.Fatalf("unexpected ack message: %q", ack.Message)
	}
	if !policy.called {
		t.Fatal("expected shard policy to be called")
	}
	if shardStore.called {
		t.Fatal("shard store should not be called when policy rejects")
	}
}

func TestReceiverPersistAndAckRejectsShardCountLimit(t *testing.T) {
	receiver, err := NewReceiver(Config{
		MaxShardCount:         1,
		MaxShardBytes:         1024,
		ShardStore:            &stubShardStore{},
		ReceiverManifestStore: &stubManifestStore{},
	})
	if err != nil {
		t.Fatalf("new receiver: %v", err)
	}

	ack := receiver.persistAndAck("peer-count", dataFrame{
		UploadID:   "upload-count",
		ShardIndex: 0,
		ShardCount: 2,
		Payload:    []byte("ok"),
	})
	if ack.Accepted || !strings.Contains(ack.Message, "exceeds configured limit") {
		t.Fatalf("unexpected ack: %+v", ack)
	}
}

func TestReceiverPersistAndAckRejectsManifestStoreFailure(t *testing.T) {
	shardStore := &stubShardStore{}
	manifestStore := &stubManifestStore{err: errors.New("manifest failed")}

	receiver, err := NewReceiver(Config{
		MaxShardBytes:         1024,
		ShardStore:            shardStore,
		ReceiverManifestStore: manifestStore,
	})
	if err != nil {
		t.Fatalf("new receiver: %v", err)
	}

	ack := receiver.persistAndAck("peer-d", dataFrame{
		UploadID:   "upload-manifest",
		ShardIndex: 0,
		ShardCount: 1,
		Payload:    []byte("ok"),
	})
	if ack.Accepted {
		t.Fatal("expected manifest failure to reject shard")
	}
	if !strings.Contains(ack.Message, "manifest failed") {
		t.Fatalf("unexpected ack message: %q", ack.Message)
	}
	if !shardStore.called {
		t.Fatal("shard store should be called before manifest failure")
	}
}

func TestReceiverPersistAndAckRejectsInvalidMetadataAndStoreFailures(t *testing.T) {
	receiver, err := NewReceiver(Config{
		ReceiverRoot: t.TempDir(),
		ShardStore:   &failingShardStore{err: errors.New("write failed")},
		ReceiverManifestStore: &failingManifestStore{
			err: errors.New("manifest failed"),
		},
	})
	if err != nil {
		t.Fatalf("new receiver: %v", err)
	}

	invalid := receiver.persistAndAck("peer-c", dataFrame{
		UploadID:   "upload-invalid",
		ShardIndex: 2,
		ShardCount: 2,
		Payload:    []byte("x"),
	})
	if invalid.Accepted || invalid.Message != "invalid shard metadata" {
		t.Fatalf("unexpected invalid ack: %+v", invalid)
	}

	storeFail := receiver.persistAndAck("peer-c", dataFrame{
		UploadID:   "upload-store",
		ShardIndex: 0,
		ShardCount: 1,
		Payload:    []byte("x"),
	})
	if storeFail.Accepted || !strings.Contains(storeFail.Message, "write failed") {
		t.Fatalf("unexpected shard store failure ack: %+v", storeFail)
	}
}

func TestReceiverHandleStreamRejectsMalformedAndAckFrames(t *testing.T) {
	mn, err := mocknet.FullMeshConnected(2)
	if err != nil {
		t.Fatalf("create mocknet: %v", err)
	}
	defer mn.Close()

	ids := mn.Peers()
	senderHost := mn.Host(ids[0])
	receiverHost := mn.Host(ids[1])

	receiver, err := NewReceiver(Config{
		ReceiverRoot: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("new receiver: %v", err)
	}
	defer receiver.Close()
	if err := receiver.Register(context.Background(), receiverHost, nil); err != nil {
		t.Fatalf("register receiver: %v", err)
	}

	t.Run("short-wire-read", func(t *testing.T) {
		stream, err := senderHost.NewStream(context.Background(), receiverHost.ID(), protocol.ID(receiver.cfg.ProtocolID))
		if err != nil {
			t.Fatalf("open stream: %v", err)
		}
		if _, err := stream.Write([]byte{0x00, 0x01}); err != nil {
			t.Fatalf("write short frame: %v", err)
		}
		_ = stream.Close()
		time.Sleep(50 * time.Millisecond)
	})

	t.Run("short-data-frame", func(t *testing.T) {
		stream, err := senderHost.NewStream(context.Background(), receiverHost.ID(), protocol.ID(receiver.cfg.ProtocolID))
		if err != nil {
			t.Fatalf("open stream: %v", err)
		}
		if _, err := stream.Write([]byte{0, 0, 0, 1, frameTypeData}); err != nil {
			t.Fatalf("write malformed data frame: %v", err)
		}
		_ = stream.Close()
		time.Sleep(50 * time.Millisecond)
	})

	t.Run("invalid-frame-type", func(t *testing.T) {
		stream, err := senderHost.NewStream(context.Background(), receiverHost.ID(), protocol.ID(receiver.cfg.ProtocolID))
		if err != nil {
			t.Fatalf("open stream: %v", err)
		}
		if _, err := stream.Write([]byte{0, 0, 0, 1, 0xff}); err != nil {
			t.Fatalf("write invalid frame: %v", err)
		}
		_ = stream.Close()
		time.Sleep(50 * time.Millisecond)
	})

	t.Run("ack-ignored", func(t *testing.T) {
		stream, err := senderHost.NewStream(context.Background(), receiverHost.ID(), protocol.ID(receiver.cfg.ProtocolID))
		if err != nil {
			t.Fatalf("open stream: %v", err)
		}
		ackBytes, err := encodeAckFrame(ackFrame{
			UploadID:   "upload-ack",
			ShardIndex: 0,
			Accepted:   true,
			Message:    "ok",
		})
		if err != nil {
			t.Fatalf("encode ack: %v", err)
		}
		if _, err := stream.Write(ackBytes); err != nil {
			t.Fatalf("write ack frame: %v", err)
		}
		_ = stream.Close()
		time.Sleep(50 * time.Millisecond)
	})
}

func TestReceiverRegisterRejectsDuplicateRegistrationAndCloseWithoutRegister(t *testing.T) {
	mn, err := mocknet.FullMeshConnected(1)
	if err != nil {
		t.Fatalf("create mocknet: %v", err)
	}
	defer mn.Close()

	host := mn.Host(mn.Peers()[0])
	receiver, err := NewReceiver(Config{})
	if err != nil {
		t.Fatalf("new receiver: %v", err)
	}
	if err := receiver.Close(); err != nil {
		t.Fatalf("close before register: %v", err)
	}
	if err := receiver.Register(context.Background(), host, nil); err != nil {
		t.Fatalf("register receiver: %v", err)
	}
	if err := receiver.Register(context.Background(), host, nil); err == nil {
		t.Fatal("expected duplicate registration error")
	}
}

func TestReceiverRegisterRejectsNilHost(t *testing.T) {
	receiver, err := NewReceiver(Config{})
	if err != nil {
		t.Fatalf("new receiver: %v", err)
	}
	if err := receiver.Register(context.Background(), nil, nil); err == nil {
		t.Fatal("expected nil host error")
	}
}

type stubShardStore struct {
	called bool
}

func (s *stubShardStore) WriteShard(context.Context, ShardWriteRequest) (ShardWriteResult, error) {
	s.called = true
	return ShardWriteResult{
		Path:  "/tmp/shard",
		Bytes: 1,
	}, nil
}

type stubManifestStore struct {
	called bool
	err    error
}

func (s *stubManifestStore) SaveReceiverShard(context.Context, ReceiverManifest) (string, error) {
	s.called = true
	if s.err != nil {
		return "", s.err
	}
	return "/tmp/manifest.json", nil
}

type stubShardPolicy struct {
	called bool
	err    error
}

func (s *stubShardPolicy) ValidateShard(context.Context, ShardValidationRequest) error {
	s.called = true
	return s.err
}

type stubRouting struct {
	provided bool
}

type failingShardStore struct {
	err error
}

func (s *failingShardStore) WriteShard(context.Context, ShardWriteRequest) (ShardWriteResult, error) {
	return ShardWriteResult{}, s.err
}

type failingManifestStore struct {
	err error
}

func (s *failingManifestStore) SaveReceiverShard(context.Context, ReceiverManifest) (string, error) {
	return "", s.err
}

func (s *stubRouting) Provide(context.Context, cid.Cid, bool) error {
	s.provided = true
	return nil
}

func (s *stubRouting) FindProvidersAsync(context.Context, cid.Cid, int) <-chan peer.AddrInfo {
	ch := make(chan peer.AddrInfo)
	close(ch)
	return ch
}

func (s *stubRouting) FindPeer(context.Context, peer.ID) (peer.AddrInfo, error) {
	return peer.AddrInfo{}, errors.New("not implemented")
}

func (s *stubRouting) PutValue(context.Context, string, []byte, ...routingcore.Option) error {
	return nil
}

func (s *stubRouting) GetValue(context.Context, string, ...routingcore.Option) ([]byte, error) {
	return nil, errors.New("not found")
}

func (s *stubRouting) SearchValue(context.Context, string, ...routingcore.Option) (<-chan []byte, error) {
	ch := make(chan []byte)
	close(ch)
	return ch, nil
}

func (s *stubRouting) Bootstrap(context.Context) error {
	return nil
}
