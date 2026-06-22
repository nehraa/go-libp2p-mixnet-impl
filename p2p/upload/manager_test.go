package upload

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	mocknet "github.com/libp2p/go-libp2p/p2p/net/mock"

	"github.com/libp2p/go-libp2p/p2p/hub"
)

func TestManagerBeginUploadRejectsDuplicateID(t *testing.T) {
	manager := &Manager{
		active: make(map[string]struct{}),
	}

	if err := manager.beginUpload("upload-1"); err != nil {
		t.Fatalf("begin upload first call: %v", err)
	}
	if err := manager.beginUpload("upload-1"); !errors.Is(err, ErrUploadInProgress) {
		t.Fatalf("expected ErrUploadInProgress, got %v", err)
	}

	manager.endUpload("upload-1")
	if err := manager.beginUpload("upload-1"); err != nil {
		t.Fatalf("begin upload after end: %v", err)
	}
}

func TestManagerWaitAckTimeout(t *testing.T) {
	manager := &Manager{
		cfg: Config{
			AckTimeout: 20 * time.Millisecond,
		},
	}

	ack, err := manager.waitAck(context.Background(), make(chan ackFrame))
	if !errors.Is(err, ErrAckTimeout) {
		t.Fatalf("expected ErrAckTimeout, got ack=%+v err=%v", ack, err)
	}
}

func TestManagerClearStreamBufferDeletesEntry(t *testing.T) {
	manager := &Manager{
		buffers: map[string][]byte{
			"stream-1": []byte("abc"),
		},
	}

	manager.clearStreamBuffer("stream-1")
	if _, ok := manager.buffers["stream-1"]; ok {
		t.Fatal("expected stream buffer entry to be deleted")
	}
}

func TestManagerMaxConcurrencyUsesConfigLimit(t *testing.T) {
	manager := &Manager{
		cfg: Config{
			MaxConcurrency: 2,
		},
	}

	if got := manager.maxConcurrency(5); got != 2 {
		t.Fatalf("expected max concurrency 2, got %d", got)
	}
	if got := manager.maxConcurrency(1); got != 1 {
		t.Fatalf("expected max concurrency 1, got %d", got)
	}
}

func TestManagerResolvePeersRejectsNilResolver(t *testing.T) {
	manager := &Manager{}

	_, err := manager.resolvePeers(context.Background(), nil, 1)
	if !errors.Is(err, ErrResolverUnavailable) {
		t.Fatalf("expected resolver unavailable, got %v", err)
	}
}

func TestManagerResolvePeersRejectsDuplicatePeers(t *testing.T) {
	mn, err := mocknet.FullMeshConnected(1)
	if err != nil {
		t.Fatalf("create mocknet: %v", err)
	}
	defer mn.Close()

	host := mn.Host(mn.Peers()[0])
	manager := &Manager{
		host: host,
		cfg:  Config{ProtocolID: "/upload/test"},
		resolver: resolverStub{peers: []peer.AddrInfo{
			{ID: peer.ID("peer-1"), Addrs: host.Addrs()},
			{ID: peer.ID("peer-1"), Addrs: host.Addrs()},
		}},
	}

	_, err = manager.resolvePeers(context.Background(), nil, 2)
	if err == nil || !strings.Contains(err.Error(), "duplicate peer") {
		t.Fatalf("expected duplicate peer error, got %v", err)
	}
}

func TestManagerCreateReceptorsCleansUpAfterDuplicateBinding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mn, err := mocknet.FullMeshConnected(2)
	if err != nil {
		t.Fatalf("create mocknet: %v", err)
	}
	defer mn.Close()

	ids := mn.Peers()
	managerHost := mn.Host(ids[0])
	targetHost := mn.Host(ids[1])

	manager, err := NewManager(managerHost, nil, Config{ManifestRoot: t.TempDir()})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer manager.Close()

	peers := []peer.AddrInfo{
		{ID: targetHost.ID(), Addrs: targetHost.Addrs()},
		{ID: targetHost.ID(), Addrs: targetHost.Addrs()},
	}

	_, err = manager.createReceptors(ctx, peers)
	if err == nil {
		t.Fatal("expected duplicate binding error")
	}
	if len(manager.hub.Snapshots()) != 0 {
		t.Fatalf("expected cleanup to remove receptors, got %d", len(manager.hub.Snapshots()))
	}
}

func TestManagerSendShardRejectsOversizeFrame(t *testing.T) {
	manager := &Manager{
		cfg: Config{
			MaxFrameSize: 4,
		},
	}

	errs := make(chan error, 1)
	result := manager.sendShard(
		context.Background(),
		"upload-1",
		SuccessModeWriteAccepted,
		ShardView{Index: 0, Start: 0, End: 1, Data: []byte("payload")},
		1,
		peer.AddrInfo{ID: peer.ID("peer-1")},
		&hub.Receptor{},
		errs,
	)
	if result.Status != "failed" {
		t.Fatalf("expected failed result, got %+v", result)
	}
	if len(errs) == 0 {
		t.Fatal("expected send error to be reported")
	}
}

func TestManagerSendWithReconnectReturnsErrorForMissingStream(t *testing.T) {
	mn, err := mocknet.FullMeshConnected(1)
	if err != nil {
		t.Fatalf("create mocknet: %v", err)
	}
	defer mn.Close()

	host := mn.Host(mn.Peers()[0])
	manager, err := NewManager(host, nil, Config{ManifestRoot: t.TempDir()})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer manager.Close()

	err = manager.sendWithReconnect(context.Background(), &hub.Receptor{}, []byte("abc"))
	if err == nil {
		t.Fatal("expected reconnect error")
	}
}

func TestManagerHandleEventDataDeliversAckAndDropsBadBuffer(t *testing.T) {
	manager := &Manager{
		cfg: Config{MaxFrameSize: 1024},
		ackWaiters: map[ackKey]chan ackFrame{
			{uploadID: "upload-1", shardIndex: 3}: make(chan ackFrame, 1),
		},
		buffers: make(map[string][]byte),
	}

	ackBytes, err := encodeAckFrame(ackFrame{
		UploadID:   "upload-1",
		ShardIndex: 3,
		Accepted:   true,
		Message:    "ok",
	})
	if err != nil {
		t.Fatalf("encode ack: %v", err)
	}
	manager.handleEventData("stream-1", ackBytes)

	select {
	case ack := <-manager.ackWaiters[ackKey{uploadID: "upload-1", shardIndex: 3}]:
		if !ack.Accepted || ack.Message != "ok" {
			t.Fatalf("unexpected ack: %+v", ack)
		}
	default:
		t.Fatal("expected ack to be delivered")
	}

	manager.cfg.MaxFrameSize = 4
	manager.buffers["stream-2"] = []byte{0, 0, 0, 9}
	manager.handleEventData("stream-2", []byte{1, 2, 3, 4, 5})
	if _, ok := manager.buffers["stream-2"]; ok {
		t.Fatal("expected invalid buffer to be cleared")
	}
}

func TestManagerRunLoopsExitWhenHubCloses(t *testing.T) {
	mn, err := mocknet.FullMeshConnected(1)
	if err != nil {
		t.Fatalf("create mocknet: %v", err)
	}
	defer mn.Close()

	host := mn.Host(mn.Peers()[0])
	hb, err := hub.New(host, hub.Config{ProtocolID: "/upload/test"})
	if err != nil {
		t.Fatalf("create hub: %v", err)
	}

	manager := &Manager{
		ctx: context.Background(),
		hub: hb,
		cfg: Config{MaxFrameSize: 1024},
	}

	eventDone := make(chan struct{})
	metricsDone := make(chan struct{})
	go func() {
		manager.runEventLoop()
		close(eventDone)
	}()
	go func() {
		manager.runMetricsLoop()
		close(metricsDone)
	}()

	if err := hb.Close(); err != nil {
		t.Fatalf("close hub: %v", err)
	}

	select {
	case <-eventDone:
	case <-time.After(5 * time.Second):
		t.Fatal("event loop did not exit")
	}
	select {
	case <-metricsDone:
	case <-time.After(5 * time.Second):
		t.Fatal("metrics loop did not exit")
	}
}

func TestManagerUploadRejectsInvalidBufferAndPeerCountMismatch(t *testing.T) {
	mn, err := mocknet.FullMeshConnected(1)
	if err != nil {
		t.Fatalf("create mocknet: %v", err)
	}
	defer mn.Close()

	host := mn.Host(mn.Peers()[0])
	manager := &Manager{
		cfg: Config{
			ProtocolID:         "/upload/test",
			ManifestRoot:       t.TempDir(),
			DefaultSuccessMode: SuccessModeAckOnPersist,
		},
		host:          host,
		resolver:      resolverStub{peers: []peer.AddrInfo{{ID: peer.ID("peer-1")}}},
		manifestStore: &stubSenderManifestStore{},
		active:        make(map[string]struct{}),
	}

	if _, err := manager.Upload(context.Background(), UploadRequest{
		UploadID:  "upload-empty",
		Buffer:    nil,
		Delimiter: []byte("|"),
	}); err == nil {
		t.Fatal("expected empty buffer error")
	}

	if _, err := manager.Upload(context.Background(), UploadRequest{
		UploadID:           "upload-mismatch",
		Buffer:             []byte("a|b"),
		Delimiter:          []byte("|"),
		ExpectedShardCount: 2,
		TargetPeers:        []peer.AddrInfo{{ID: peer.ID("peer-1")}},
	}); err == nil {
		t.Fatal("expected peer count mismatch error")
	}
}

func TestManagerUploadReportsManifestStoreFailureAfterSuccessfulSend(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mn, err := mocknet.FullMeshConnected(2)
	if err != nil {
		t.Fatalf("create mocknet: %v", err)
	}
	defer mn.Close()

	ids := mn.Peers()
	senderHost := mn.Host(ids[0])
	receiverHost := mn.Host(ids[1])
	receiverHost.SetStreamHandler("/upload/test", func(stream network.Stream) {
		defer stream.Close()
		_, _ = io.Copy(io.Discard, stream)
	})

	manager, err := NewManager(senderHost, nil, Config{
		ManifestRoot:       t.TempDir(),
		ProtocolID:         "/upload/test",
		DefaultSuccessMode: SuccessModeWriteAccepted,
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer manager.Close()
	manager.manifestStore = &failingSenderManifestStore{err: errors.New("manifest failed")}

	res, err := manager.Upload(ctx, UploadRequest{
		UploadID:           "upload-manifest-failure",
		Buffer:             []byte("payload"),
		Delimiter:          []byte(","),
		ExpectedShardCount: 1,
		TargetPeers:        []peer.AddrInfo{{ID: receiverHost.ID(), Addrs: receiverHost.Addrs()}},
		SuccessMode:        SuccessModeWriteAccepted,
	})
	if err == nil || !strings.Contains(err.Error(), "manifest failed") {
		t.Fatalf("expected manifest failure, got res=%+v err=%v", res, err)
	}
}

func TestManagerSendShardTimesOutWaitingForAck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mn, err := mocknet.FullMeshConnected(2)
	if err != nil {
		t.Fatalf("create mocknet: %v", err)
	}
	defer mn.Close()

	ids := mn.Peers()
	senderHost := mn.Host(ids[0])
	receiverHost := mn.Host(ids[1])
	receiverHost.SetStreamHandler("/upload/test", func(stream network.Stream) {
		defer stream.Close()
		_, _ = io.Copy(io.Discard, stream)
	})

	manager, err := NewManager(senderHost, nil, Config{
		ManifestRoot: t.TempDir(),
		ProtocolID:   "/upload/test",
		AckTimeout:   20 * time.Millisecond,
		SendTimeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer manager.Close()

	target := peer.AddrInfo{ID: receiverHost.ID(), Addrs: receiverHost.Addrs()}
	receptors, err := manager.createReceptors(ctx, []peer.AddrInfo{target})
	if err != nil {
		t.Fatalf("create receptor: %v", err)
	}
	defer manager.cleanupReceptors(receptors)

	errs := make(chan error, 1)
	result := manager.sendShard(
		ctx,
		"upload-timeout",
		SuccessModeAckOnPersist,
		ShardView{Index: 0, Start: 0, End: 3, Data: []byte("abc")},
		1,
		target,
		receptors[0],
		errs,
	)
	if result.Status != "failed" {
		t.Fatalf("expected failed shard result, got %+v", result)
	}
	if !strings.Contains(result.Error, ErrAckTimeout.Error()) {
		t.Fatalf("expected ack timeout error, got %q", result.Error)
	}
}

type resolverStub struct {
	peers []peer.AddrInfo
}

type stubSenderManifestStore struct {
	called bool
}

func (s *stubSenderManifestStore) SaveSenderManifest(context.Context, *SenderManifest) (string, string, error) {
	s.called = true
	return "/tmp/manifest.json", "/tmp/nodes.json", nil
}

type failingSenderManifestStore struct {
	err error
}

func (s *failingSenderManifestStore) SaveSenderManifest(context.Context, *SenderManifest) (string, string, error) {
	return "", "", s.err
}

func (r resolverStub) ResolvePeers(context.Context, PeerResolveRequest) ([]peer.AddrInfo, error) {
	return append([]peer.AddrInfo(nil), r.peers...), nil
}
