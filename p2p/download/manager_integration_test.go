package download

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	mocknet "github.com/libp2p/go-libp2p/p2p/net/mock"
	uploadpkg "github.com/libp2p/go-libp2p/p2p/upload"
)

func TestDownloadStrictReconstructsFromMultipleHolders(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	mn, err := mocknet.FullMeshConnected(3)
	if err != nil {
		t.Fatalf("create mocknet: %v", err)
	}
	defer mn.Close()

	ids := mn.Peers()
	downloaderHost := mn.Host(ids[0])
	holder1Host := mn.Host(ids[1])
	holder2Host := mn.Host(ids[2])

	holder1Root := t.TempDir()
	holder2Root := t.TempDir()
	const uploadID = "download-integration-upload"
	shard0 := []byte("hello-")
	shard1 := []byte("world")

	writeShardFile(t, holder1Root, uploadID, 0, shard0)
	writeShardFile(t, holder2Root, uploadID, 1, shard1)

	holder1, err := NewHolderService(holder1Host, nil, Config{HolderRoot: holder1Root})
	if err != nil {
		t.Fatalf("new holder 1: %v", err)
	}
	defer holder1.Close()
	holder2, err := NewHolderService(holder2Host, nil, Config{HolderRoot: holder2Root})
	if err != nil {
		t.Fatalf("new holder 2: %v", err)
	}
	defer holder2.Close()

	downloaderInfo := peer.AddrInfo{ID: downloaderHost.ID(), Addrs: downloaderHost.Addrs()}
	if err := holder1.AllowRequester(ctx, downloaderInfo); err != nil {
		t.Fatalf("allow requester on holder 1: %v", err)
	}
	if err := holder2.AllowRequester(ctx, downloaderInfo); err != nil {
		t.Fatalf("allow requester on holder 2: %v", err)
	}

	manifest := signTestManifest(
		t,
		uploadID,
		[]ShardDescriptor{
			{Index: 0, HolderPeerID: holder1Host.ID().String(), Size: int64(len(shard0)), DigestAlgo: digestAlgoSHA256, Digest: HashShard(shard0)},
			{Index: 1, HolderPeerID: holder2Host.ID().String(), Size: int64(len(shard1)), DigestAlgo: digestAlgoSHA256, Digest: HashShard(shard1)},
		},
	)

	downloadRoot := t.TempDir()
	manager, err := NewManager(downloaderHost, nil, Config{DownloadRoot: downloadRoot})
	if err != nil {
		t.Fatalf("new download manager: %v", err)
	}
	defer manager.Close()

	result, err := manager.Download(ctx, DownloadRequest{
		UploadID:       uploadID,
		SignedManifest: manifest,
		Sources: []ShardSource{
			{ShardIndex: 0, Holder: peer.AddrInfo{ID: holder1Host.ID(), Addrs: holder1Host.Addrs()}},
			{ShardIndex: 1, Holder: peer.AddrInfo{ID: holder2Host.ID(), Addrs: holder2Host.Addrs()}},
		},
		Mode: ReconstructionModeStrict,
	})
	if err != nil {
		t.Fatalf("download failed: %v", err)
	}
	output, err := os.ReadFile(result.OutputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(output) != "hello-world" {
		t.Fatalf("unexpected reconstructed output: %q", string(output))
	}
}

func TestDownloadStrictDetectsTamperedShard(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	mn, err := mocknet.FullMeshConnected(2)
	if err != nil {
		t.Fatalf("create mocknet: %v", err)
	}
	defer mn.Close()

	ids := mn.Peers()
	downloaderHost := mn.Host(ids[0])
	holderHost := mn.Host(ids[1])

	holderRoot := t.TempDir()
	const uploadID = "tamper-upload"
	shard := []byte("actual-data")
	writeShardFile(t, holderRoot, uploadID, 0, shard)

	holderService, err := NewHolderService(holderHost, nil, Config{HolderRoot: holderRoot})
	if err != nil {
		t.Fatalf("new holder: %v", err)
	}
	defer holderService.Close()
	if err := holderService.AllowRequester(ctx, peer.AddrInfo{ID: downloaderHost.ID(), Addrs: downloaderHost.Addrs()}); err != nil {
		t.Fatalf("allow requester: %v", err)
	}

	manifest := signTestManifest(
		t,
		uploadID,
		[]ShardDescriptor{
			{
				Index:        0,
				HolderPeerID: holderHost.ID().String(),
				Size:         int64(len(shard)),
				DigestAlgo:   digestAlgoSHA256,
				Digest:       HashShard([]byte("tampered-reference")),
			},
		},
	)

	manager, err := NewManager(downloaderHost, nil, Config{DownloadRoot: t.TempDir()})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer manager.Close()

	result, err := manager.Download(ctx, DownloadRequest{
		UploadID:       uploadID,
		SignedManifest: manifest,
		Sources: []ShardSource{
			{ShardIndex: 0, Holder: peer.AddrInfo{ID: holderHost.ID(), Addrs: holderHost.Addrs()}},
		},
		Mode: ReconstructionModeStrict,
	})
	if err == nil {
		t.Fatal("expected strict download to fail on digest mismatch")
	}
	if len(result.InvalidShards) != 1 || result.InvalidShards[0] != 0 {
		t.Fatalf("expected invalid shard index 0, got %+v", result.InvalidShards)
	}
}

func TestDownloadAfterUploadAcrossLocalNodes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mn, err := mocknet.FullMeshConnected(4)
	if err != nil {
		t.Fatalf("create mocknet: %v", err)
	}
	defer mn.Close()

	ids := mn.Peers()
	uploaderHost := mn.Host(ids[0])
	holder1Host := mn.Host(ids[1])
	holder2Host := mn.Host(ids[2])
	downloaderHost := mn.Host(ids[3])

	holder1Root := t.TempDir()
	holder2Root := t.TempDir()
	const uploadID = "upload-download-flow"

	receiver1, err := uploadpkg.NewReceiver(uploadpkg.Config{ReceiverRoot: holder1Root})
	if err != nil {
		t.Fatalf("new upload receiver 1: %v", err)
	}
	defer receiver1.Close()
	receiver2, err := uploadpkg.NewReceiver(uploadpkg.Config{ReceiverRoot: holder2Root})
	if err != nil {
		t.Fatalf("new upload receiver 2: %v", err)
	}
	defer receiver2.Close()
	if err := receiver1.Register(ctx, holder1Host, nil); err != nil {
		t.Fatalf("register upload receiver 1: %v", err)
	}
	if err := receiver2.Register(ctx, holder2Host, nil); err != nil {
		t.Fatalf("register upload receiver 2: %v", err)
	}

	uploaderManager, err := uploadpkg.NewManager(uploaderHost, nil, uploadpkg.Config{ManifestRoot: t.TempDir()})
	if err != nil {
		t.Fatalf("new upload manager: %v", err)
	}
	defer uploaderManager.Close()

	_, err = uploaderManager.Upload(ctx, uploadpkg.UploadRequest{
		UploadID:           uploadID,
		Buffer:             []byte("alpha|beta"),
		Delimiter:          []byte("|"),
		ExpectedShardCount: 2,
		TargetPeers: []peer.AddrInfo{
			{ID: holder1Host.ID(), Addrs: holder1Host.Addrs()},
			{ID: holder2Host.ID(), Addrs: holder2Host.Addrs()},
		},
		SuccessMode: uploadpkg.SuccessModeAckOnPersist,
	})
	if err != nil {
		t.Fatalf("upload failed: %v", err)
	}

	holderService1, err := NewHolderService(holder1Host, nil, Config{HolderRoot: holder1Root})
	if err != nil {
		t.Fatalf("new holder service 1: %v", err)
	}
	defer holderService1.Close()
	holderService2, err := NewHolderService(holder2Host, nil, Config{HolderRoot: holder2Root})
	if err != nil {
		t.Fatalf("new holder service 2: %v", err)
	}
	defer holderService2.Close()

	downloaderInfo := peer.AddrInfo{ID: downloaderHost.ID(), Addrs: downloaderHost.Addrs()}
	if err := holderService1.AllowRequester(ctx, downloaderInfo); err != nil {
		t.Fatalf("allow requester on holder 1: %v", err)
	}
	if err := holderService2.AllowRequester(ctx, downloaderInfo); err != nil {
		t.Fatalf("allow requester on holder 2: %v", err)
	}

	manifest := signTestManifest(
		t,
		uploadID,
		[]ShardDescriptor{
			{Index: 0, HolderPeerID: holder1Host.ID().String(), Size: int64(len("alpha")), DigestAlgo: digestAlgoSHA256, Digest: HashShard([]byte("alpha"))},
			{Index: 1, HolderPeerID: holder2Host.ID().String(), Size: int64(len("beta")), DigestAlgo: digestAlgoSHA256, Digest: HashShard([]byte("beta"))},
		},
	)

	downloadManager, err := NewManager(downloaderHost, nil, Config{DownloadRoot: t.TempDir()})
	if err != nil {
		t.Fatalf("new download manager: %v", err)
	}
	defer downloadManager.Close()

	result, err := downloadManager.Download(ctx, DownloadRequest{
		UploadID:       uploadID,
		SignedManifest: manifest,
		Sources: []ShardSource{
			{ShardIndex: 0, Holder: peer.AddrInfo{ID: holder1Host.ID(), Addrs: holder1Host.Addrs()}},
			{ShardIndex: 1, Holder: peer.AddrInfo{ID: holder2Host.ID(), Addrs: holder2Host.Addrs()}},
		},
		Mode: ReconstructionModeStrict,
	})
	if err != nil {
		t.Fatalf("download failed: %v", err)
	}
	output, err := os.ReadFile(result.OutputPath)
	if err != nil {
		t.Fatalf("read downloaded output: %v", err)
	}
	if string(output) != "alphabeta" {
		t.Fatalf("unexpected reconstructed output: %q", string(output))
	}
}

func TestHolderServesSameShardToMultipleDownloadersInParallel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	mn, err := mocknet.FullMeshConnected(3)
	if err != nil {
		t.Fatalf("create mocknet: %v", err)
	}
	defer mn.Close()

	ids := mn.Peers()
	holderHost := mn.Host(ids[0])
	downloaderAHost := mn.Host(ids[1])
	downloaderBHost := mn.Host(ids[2])

	holderRoot := t.TempDir()
	const uploadID = "parallel-holder-upload"
	shard := []byte("shared-shard-data")
	writeShardFile(t, holderRoot, uploadID, 0, shard)

	holderService, err := NewHolderService(holderHost, nil, Config{HolderRoot: holderRoot})
	if err != nil {
		t.Fatalf("new holder service: %v", err)
	}
	defer holderService.Close()
	if err := holderService.AllowRequester(ctx, peer.AddrInfo{ID: downloaderAHost.ID(), Addrs: downloaderAHost.Addrs()}); err != nil {
		t.Fatalf("allow requester A: %v", err)
	}
	if err := holderService.AllowRequester(ctx, peer.AddrInfo{ID: downloaderBHost.ID(), Addrs: downloaderBHost.Addrs()}); err != nil {
		t.Fatalf("allow requester B: %v", err)
	}

	manifest := signTestManifest(
		t,
		uploadID,
		[]ShardDescriptor{
			{
				Index:        0,
				HolderPeerID: holderHost.ID().String(),
				Size:         int64(len(shard)),
				DigestAlgo:   digestAlgoSHA256,
				Digest:       HashShard(shard),
			},
		},
	)

	managerA, err := NewManager(downloaderAHost, nil, Config{DownloadRoot: t.TempDir()})
	if err != nil {
		t.Fatalf("new download manager A: %v", err)
	}
	defer managerA.Close()
	managerB, err := NewManager(downloaderBHost, nil, Config{DownloadRoot: t.TempDir()})
	if err != nil {
		t.Fatalf("new download manager B: %v", err)
	}
	defer managerB.Close()

	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	runDownload := func(manager *Manager) {
		defer wg.Done()
		result, err := manager.Download(ctx, DownloadRequest{
			UploadID:       uploadID,
			SignedManifest: manifest,
			Sources: []ShardSource{
				{ShardIndex: 0, Holder: peer.AddrInfo{ID: holderHost.ID(), Addrs: holderHost.Addrs()}},
			},
			Mode: ReconstructionModeStrict,
		})
		if err != nil {
			errCh <- err
			return
		}
		raw, readErr := os.ReadFile(result.OutputPath)
		if readErr != nil {
			errCh <- readErr
			return
		}
		if string(raw) != string(shard) {
			errCh <- os.ErrInvalid
			return
		}
	}

	wg.Add(2)
	go runDownload(managerA)
	go runDownload(managerB)
	wg.Wait()
	close(errCh)
	for downloadErr := range errCh {
		if downloadErr == os.ErrInvalid {
			t.Fatal("parallel download returned unexpected output")
		}
		t.Fatalf("parallel download failed: %v", downloadErr)
	}
}

func TestDownloadFailsWhenHolderShardMissing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	mn, err := mocknet.FullMeshConnected(2)
	if err != nil {
		t.Fatalf("create mocknet: %v", err)
	}
	defer mn.Close()

	ids := mn.Peers()
	downloaderHost := mn.Host(ids[0])
	holderHost := mn.Host(ids[1])

	holderRoot := t.TempDir()
	const uploadID = "missing-holder-shard"
	holderService, err := NewHolderService(holderHost, nil, Config{HolderRoot: holderRoot})
	if err != nil {
		t.Fatalf("new holder service: %v", err)
	}
	defer holderService.Close()
	if err := holderService.AllowRequester(ctx, peer.AddrInfo{ID: downloaderHost.ID(), Addrs: downloaderHost.Addrs()}); err != nil {
		t.Fatalf("allow requester: %v", err)
	}

	manifest := signTestManifest(
		t,
		uploadID,
		[]ShardDescriptor{
			{
				Index:        0,
				HolderPeerID: holderHost.ID().String(),
				Size:         4,
				DigestAlgo:   digestAlgoSHA256,
				Digest:       HashShard([]byte("data")),
			},
		},
	)

	manager, err := NewManager(downloaderHost, nil, Config{DownloadRoot: t.TempDir(), RetryCount: 0})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer manager.Close()

	result, err := manager.Download(ctx, DownloadRequest{
		UploadID:       uploadID,
		SignedManifest: manifest,
		Sources: []ShardSource{
			{ShardIndex: 0, Holder: peer.AddrInfo{ID: holderHost.ID(), Addrs: holderHost.Addrs()}},
		},
		Mode: ReconstructionModeStrict,
	})
	if err == nil {
		t.Fatal("expected download error when holder shard is missing")
	}
	if len(result.ShardResults) != 1 {
		t.Fatalf("expected one shard result, got %d", len(result.ShardResults))
	}
	if result.ShardResults[0].Status != "failed" {
		t.Fatalf("expected failed shard status, got %s", result.ShardResults[0].Status)
	}
}

func writeShardFile(t *testing.T, root string, uploadID string, shardIndex int, data []byte) {
	t.Helper()
	dir := filepath.Join(root, uploadID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create shard dir: %v", err)
	}
	path := filepath.Join(dir, formatShardFile(shardIndex))
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write shard file: %v", err)
	}
}

func signTestManifest(t *testing.T, uploadID string, shards []ShardDescriptor) SignedShardManifest {
	t.Helper()

	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	manifest := ShardManifest{
		Version:     manifestVersion,
		UploadID:    uploadID,
		TotalShards: len(shards),
		CreatedAt:   time.Now().UTC(),
		Shards:      shards,
	}
	signed, err := SignManifest(manifest, priv)
	if err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	return signed
}
