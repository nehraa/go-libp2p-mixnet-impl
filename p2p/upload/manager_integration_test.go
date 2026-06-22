package upload

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p/core/peer"
	routingcore "github.com/libp2p/go-libp2p/core/routing"
	mocknet "github.com/libp2p/go-libp2p/p2p/net/mock"
)

type staticRouting struct {
	providers []peer.AddrInfo
	peers     map[peer.ID]peer.AddrInfo
}

func (s *staticRouting) Provide(context.Context, cid.Cid, bool) error { return nil }

func (s *staticRouting) FindProvidersAsync(ctx context.Context, _ cid.Cid, count int) <-chan peer.AddrInfo {
	ch := make(chan peer.AddrInfo, len(s.providers))
	go func() {
		defer close(ch)
		limit := len(s.providers)
		if count > 0 && count < limit {
			limit = count
		}
		for i := 0; i < limit; i++ {
			select {
			case <-ctx.Done():
				return
			case ch <- s.providers[i]:
			}
		}
	}()
	return ch
}

func (s *staticRouting) FindPeer(_ context.Context, id peer.ID) (peer.AddrInfo, error) {
	info, ok := s.peers[id]
	if !ok {
		return peer.AddrInfo{}, errors.New("peer not found")
	}
	return info, nil
}

func (s *staticRouting) PutValue(context.Context, string, []byte, ...routingcore.Option) error {
	return nil
}

func (s *staticRouting) GetValue(context.Context, string, ...routingcore.Option) ([]byte, error) {
	return nil, errors.New("value not found")
}

func (s *staticRouting) SearchValue(context.Context, string, ...routingcore.Option) (<-chan []byte, error) {
	ch := make(chan []byte)
	close(ch)
	return ch, nil
}

func (s *staticRouting) Bootstrap(context.Context) error { return nil }

func TestManagerUploadExplicitPeers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	mn, err := mocknet.FullMeshConnected(4)
	if err != nil {
		t.Fatalf("create mocknet: %v", err)
	}
	defer mn.Close()

	ids := mn.Peers()
	senderHost := mn.Host(ids[0])
	receiverHosts := []struct {
		info peer.AddrInfo
		root string
		recv *Receiver
	}{
		{info: peer.AddrInfo{ID: ids[1], Addrs: mn.Host(ids[1]).Addrs()}, root: t.TempDir()},
		{info: peer.AddrInfo{ID: ids[2], Addrs: mn.Host(ids[2]).Addrs()}, root: t.TempDir()},
		{info: peer.AddrInfo{ID: ids[3], Addrs: mn.Host(ids[3]).Addrs()}, root: t.TempDir()},
	}

	for i := range receiverHosts {
		h := mn.Host(receiverHosts[i].info.ID)
		recv, err := NewReceiver(Config{
			ReceiverRoot: receiverHosts[i].root,
		})
		if err != nil {
			t.Fatalf("new receiver %d: %v", i, err)
		}
		if err := recv.Register(ctx, h, nil); err != nil {
			t.Fatalf("register receiver %d: %v", i, err)
		}
		receiverHosts[i].recv = recv
		defer receiverHosts[i].recv.Close()
	}

	manager, err := NewManager(senderHost, nil, Config{
		ManifestRoot: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer manager.Close()

	targets := make([]peer.AddrInfo, 0, len(receiverHosts))
	for _, entry := range receiverHosts {
		targets = append(targets, entry.info)
	}
	res, err := manager.Upload(ctx, UploadRequest{
		UploadID:           "explicit-upload",
		Buffer:             []byte("alpha|beta|gamma"),
		Delimiter:          []byte("|"),
		ExpectedShardCount: 3,
		TargetPeers:        targets,
		SuccessMode:        SuccessModeAckOnPersist,
	})
	if err != nil {
		t.Fatalf("upload failed: %v", err)
	}
	if len(res.ShardResults) != 3 {
		t.Fatalf("expected 3 shard results, got %d", len(res.ShardResults))
	}
	if _, statErr := os.Stat(res.ManifestPath); statErr != nil {
		t.Fatalf("expected manifest path %s to exist: %v", res.ManifestPath, statErr)
	}
	if _, statErr := os.Stat(res.NodeIDsPath); statErr != nil {
		t.Fatalf("expected node ids path %s to exist: %v", res.NodeIDsPath, statErr)
	}

	expected := []string{"alpha", "beta", "gamma"}
	for i, entry := range receiverHosts {
		path := filepath.Join(entry.root, "explicit-upload", formatShardFile(i))
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read receiver shard %d: %v", i, readErr)
		}
		if string(raw) != expected[i] {
			t.Fatalf("receiver shard %d mismatch: got %q want %q", i, string(raw), expected[i])
		}
	}
}

func TestManagerUploadWithDiscovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	mn, err := mocknet.FullMeshConnected(3)
	if err != nil {
		t.Fatalf("create mocknet: %v", err)
	}
	defer mn.Close()

	ids := mn.Peers()
	senderHost := mn.Host(ids[0])
	r1 := mn.Host(ids[1])
	r2 := mn.Host(ids[2])

	r1Root := t.TempDir()
	r2Root := t.TempDir()

	recv1, err := NewReceiver(Config{ReceiverRoot: r1Root})
	if err != nil {
		t.Fatalf("new receiver 1: %v", err)
	}
	defer recv1.Close()
	recv2, err := NewReceiver(Config{ReceiverRoot: r2Root})
	if err != nil {
		t.Fatalf("new receiver 2: %v", err)
	}
	defer recv2.Close()
	if err := recv1.Register(ctx, r1, nil); err != nil {
		t.Fatalf("register receiver 1: %v", err)
	}
	if err := recv2.Register(ctx, r2, nil); err != nil {
		t.Fatalf("register receiver 2: %v", err)
	}

	providers := []peer.AddrInfo{
		{ID: r1.ID(), Addrs: r1.Addrs()},
		{ID: r2.ID(), Addrs: r2.Addrs()},
	}
	peerMap := map[peer.ID]peer.AddrInfo{
		senderHost.ID(): {ID: senderHost.ID(), Addrs: senderHost.Addrs()},
		r1.ID():         providers[0],
		r2.ID():         providers[1],
	}
	route := &staticRouting{
		providers: providers,
		peers:     peerMap,
	}

	manager, err := NewManager(senderHost, route, Config{
		ManifestRoot:       t.TempDir(),
		SelectionMode:      "rtt",
		SamplingSize:       2,
		RandomnessFactor:   0.1,
		DiscoveryNamespace: "/upload/discovery/test/v1",
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer manager.Close()

	res, err := manager.Upload(ctx, UploadRequest{
		UploadID:           "discovery-upload",
		Buffer:             []byte("left|right"),
		Delimiter:          []byte("|"),
		ExpectedShardCount: 2,
	})
	if err != nil {
		t.Fatalf("upload failed: %v", err)
	}
	if len(res.SelectedPeers) != 2 {
		t.Fatalf("expected 2 selected peers, got %d", len(res.SelectedPeers))
	}
	if _, statErr := os.Stat(res.NodeIDsPath); statErr != nil {
		t.Fatalf("node ids file missing: %v", statErr)
	}
}

func TestManagerUploadWriteAcceptedMode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	mn, err := mocknet.FullMeshConnected(2)
	if err != nil {
		t.Fatalf("create mocknet: %v", err)
	}
	defer mn.Close()

	ids := mn.Peers()
	senderHost := mn.Host(ids[0])
	receiverHost := mn.Host(ids[1])

	receiverRoot := t.TempDir()
	receiver, err := NewReceiver(Config{
		ReceiverRoot: receiverRoot,
	})
	if err != nil {
		t.Fatalf("new receiver: %v", err)
	}
	defer receiver.Close()
	if err := receiver.Register(ctx, receiverHost, nil); err != nil {
		t.Fatalf("register receiver: %v", err)
	}

	manager, err := NewManager(senderHost, nil, Config{
		ManifestRoot: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer manager.Close()

	target := peer.AddrInfo{ID: receiverHost.ID(), Addrs: receiverHost.Addrs()}
	res, err := manager.Upload(ctx, UploadRequest{
		UploadID:           "write-accepted-upload",
		Buffer:             []byte("payload"),
		Delimiter:          []byte("|"),
		ExpectedShardCount: 1,
		TargetPeers:        []peer.AddrInfo{target},
		SuccessMode:        SuccessModeWriteAccepted,
	})
	if err != nil {
		t.Fatalf("upload failed: %v", err)
	}
	if len(res.ShardResults) != 1 {
		t.Fatalf("expected 1 shard result, got %d", len(res.ShardResults))
	}
	if res.ShardResults[0].Acked {
		t.Fatal("expected write_accepted upload not to wait for ack")
	}
	if res.ShardResults[0].Status != "success" {
		t.Fatalf("unexpected shard status: %s", res.ShardResults[0].Status)
	}
}

func formatShardFile(index int) string {
	return fmt.Sprintf("%06d.part", index)
}
