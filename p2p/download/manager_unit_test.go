package download

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

func TestValidateRequestStrictRejectsMissingSource(t *testing.T) {
	holder1 := generateTestPeerID(t)
	holder2 := generateTestPeerID(t)

	manifest := signTestManifest(t, "strict-upload", []ShardDescriptor{
		{Index: 0, HolderPeerID: holder1.String(), Size: 1, DigestAlgo: digestAlgoSHA256, Digest: HashShard([]byte("a"))},
		{Index: 1, HolderPeerID: holder2.String(), Size: 1, DigestAlgo: digestAlgoSHA256, Digest: HashShard([]byte("b"))},
	})
	manager := &Manager{}
	_, _, _, _, err := manager.validateRequest(DownloadRequest{
		UploadID:       "strict-upload",
		SignedManifest: manifest,
		Sources: []ShardSource{
			{ShardIndex: 0, Holder: peer.AddrInfo{ID: holder1}},
		},
		Mode: ReconstructionModeStrict,
	})
	if err == nil {
		t.Fatal("expected strict mode validation to reject missing source")
	}
}

func TestValidateRequestRejectsDuplicateSourcePeer(t *testing.T) {
	holder := generateTestPeerID(t)

	manifest := signTestManifest(t, "dup-peer-upload", []ShardDescriptor{
		{Index: 0, HolderPeerID: holder.String(), Size: 1, DigestAlgo: digestAlgoSHA256, Digest: HashShard([]byte("a"))},
		{Index: 1, HolderPeerID: holder.String(), Size: 1, DigestAlgo: digestAlgoSHA256, Digest: HashShard([]byte("b"))},
	})
	manager := &Manager{}
	_, _, _, _, err := manager.validateRequest(DownloadRequest{
		UploadID:       "dup-peer-upload",
		SignedManifest: manifest,
		Sources: []ShardSource{
			{ShardIndex: 0, Holder: peer.AddrInfo{ID: holder}},
			{ShardIndex: 1, Holder: peer.AddrInfo{ID: holder}},
		},
		Mode: ReconstructionModeBestEffort,
	})
	if err == nil {
		t.Fatal("expected duplicate peer validation failure")
	}
}

func TestValidateRequestRejectsInvalidUploadIDAndMode(t *testing.T) {
	manager := &Manager{}
	manifest := signTestManifest(t, "valid-upload", []ShardDescriptor{
		{Index: 0, HolderPeerID: generateTestPeerID(t).String(), Size: 1, DigestAlgo: digestAlgoSHA256, Digest: HashShard([]byte("a"))},
	}).Manifest

	if _, _, _, _, err := manager.validateRequest(DownloadRequest{
		UploadID:       "",
		SignedManifest: signTestManifest(t, "valid-upload", []ShardDescriptor{{Index: 0, HolderPeerID: generateTestPeerID(t).String(), Size: 1, DigestAlgo: digestAlgoSHA256, Digest: HashShard([]byte("a"))}}),
		Sources:        []ShardSource{{ShardIndex: 0, Holder: peer.AddrInfo{ID: generateTestPeerID(t)}}},
		Mode:           ReconstructionModeStrict,
	}); err == nil {
		t.Fatal("expected invalid upload id error")
	}

	if _, _, _, _, err := manager.validateRequest(DownloadRequest{
		UploadID:       manifest.UploadID,
		SignedManifest: signTestManifest(t, manifest.UploadID, []ShardDescriptor{{Index: 0, HolderPeerID: generateTestPeerID(t).String(), Size: 1, DigestAlgo: digestAlgoSHA256, Digest: HashShard([]byte("a"))}}),
		Sources:        []ShardSource{{ShardIndex: 0, Holder: peer.AddrInfo{ID: generateTestPeerID(t)}}},
		Mode:           ReconstructionMode("unsupported"),
	}); err == nil {
		t.Fatal("expected invalid mode error")
	}
}

func TestValidateRequestThresholdChecksCount(t *testing.T) {
	holder := generateTestPeerID(t)
	manifest := signTestManifest(t, "threshold-upload", []ShardDescriptor{
		{Index: 0, HolderPeerID: holder.String(), Size: 1, DigestAlgo: digestAlgoSHA256, Digest: HashShard([]byte("a"))},
		{Index: 1, HolderPeerID: holder.String(), Size: 1, DigestAlgo: digestAlgoSHA256, Digest: HashShard([]byte("b"))},
	})
	manager := &Manager{}
	_, _, _, _, err := manager.validateRequest(DownloadRequest{
		UploadID:       "threshold-upload",
		SignedManifest: manifest,
		Sources: []ShardSource{
			{ShardIndex: 0, Holder: peer.AddrInfo{ID: holder}},
		},
		Mode:      ReconstructionModeThreshold,
		Threshold: 2,
	})
	if err == nil {
		t.Fatal("expected threshold validation failure")
	}
}

func TestReconstructOutputThresholdRequiresReconstructor(t *testing.T) {
	manager := &Manager{
		cfg: Config{},
	}
	dir := t.TempDir()
	shardPath := filepath.Join(dir, "000000.part")
	if err := os.WriteFile(shardPath, []byte("payload"), 0o644); err != nil {
		t.Fatalf("write shard: %v", err)
	}

	err := manager.reconstructOutput(
		context.Background(),
		ReconstructionModeThreshold,
		1,
		1,
		[]DownloadedShard{{Index: 0, Path: shardPath, Bytes: 7}},
		filepath.Join(dir, "out.bin"),
	)
	if err == nil {
		t.Fatal("expected threshold reconstruction to fail without reconstructor")
	}
}

func TestReconstructOutputBestEffortConcatenatesAvailableShards(t *testing.T) {
	manager := &Manager{cfg: Config{}}
	dir := t.TempDir()
	shard0 := filepath.Join(dir, "000000.part")
	shard2 := filepath.Join(dir, "000002.part")
	if err := os.WriteFile(shard0, []byte("left"), 0o644); err != nil {
		t.Fatalf("write shard0: %v", err)
	}
	if err := os.WriteFile(shard2, []byte("right"), 0o644); err != nil {
		t.Fatalf("write shard2: %v", err)
	}

	outPath := filepath.Join(dir, "out.bin")
	err := manager.reconstructOutput(
		context.Background(),
		ReconstructionModeBestEffort,
		0,
		3,
		[]DownloadedShard{
			{Index: 2, Path: shard2, Bytes: 5},
			{Index: 0, Path: shard0, Bytes: 4},
		},
		outPath,
	)
	if err != nil {
		t.Fatalf("best-effort reconstruct: %v", err)
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(raw) != "leftright" {
		t.Fatalf("unexpected output: %q", string(raw))
	}
}

func TestReconstructOutputStrictRejectsMissingShardAndSortsInput(t *testing.T) {
	manager := &Manager{cfg: Config{}}
	dir := t.TempDir()
	shard0 := filepath.Join(dir, "000000.part")
	shard1 := filepath.Join(dir, "000001.part")
	if err := os.WriteFile(shard0, []byte("zero"), 0o644); err != nil {
		t.Fatalf("write shard0: %v", err)
	}
	if err := os.WriteFile(shard1, []byte("one"), 0o644); err != nil {
		t.Fatalf("write shard1: %v", err)
	}

	if err := manager.reconstructOutput(context.Background(), ReconstructionModeStrict, 0, 2, []DownloadedShard{{Index: 0, Path: shard0, Bytes: 4}}, filepath.Join(dir, "out-missing.bin")); err == nil {
		t.Fatal("expected strict reconstruction missing shard failure")
	}

	outPath := filepath.Join(dir, "out-order.bin")
	if err := manager.reconstructOutput(context.Background(), ReconstructionModeStrict, 0, 2, []DownloadedShard{{Index: 1, Path: shard1, Bytes: 3}, {Index: 0, Path: shard0, Bytes: 4}}, outPath); err != nil {
		t.Fatalf("strict reconstruction sort: %v", err)
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read reconstructed output: %v", err)
	}
	if string(raw) != "zeroone" {
		t.Fatalf("unexpected reconstructed output: %q", string(raw))
	}
}

func TestConcatShardFilesRejectsContextCancellationAndMissingFile(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "out.bin")
	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open out: %v", err)
	}
	defer out.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := concatShardFiles(ctx, []DownloadedShard{{Index: 0, Path: filepath.Join(dir, "missing.part"), Bytes: 1}}, out); err == nil {
		t.Fatal("expected context cancellation failure")
	}

	if err := concatShardFiles(context.Background(), []DownloadedShard{{Index: 0, Path: filepath.Join(dir, "missing.part"), Bytes: 1}}, out); err == nil {
		t.Fatal("expected missing shard open failure")
	}
}

func TestShardReceiverFailClosesAndCleansTempFile(t *testing.T) {
	dir := t.TempDir()
	receiver, err := newShardReceiver(
		"upload-1",
		"req-1",
		0,
		generateTestPeerID(t),
		ShardDescriptor{Index: 0, HolderPeerID: generateTestPeerID(t).String(), Size: 4, DigestAlgo: digestAlgoSHA256, Digest: HashShard([]byte("data"))},
		filepath.Join(dir, "final.part"),
		filepath.Join(dir, "temp.part"),
	)
	if err != nil {
		t.Fatalf("new shard receiver: %v", err)
	}

	receiver.fail(errors.New("forced failure"))
	<-receiver.done
	if _, statErr := os.Stat(filepath.Join(dir, "temp.part")); !os.IsNotExist(statErr) {
		t.Fatalf("expected temp file to be removed, stat err=%v", statErr)
	}
}

func TestShardReceiverHandleChunkAndEndFailures(t *testing.T) {
	dir := t.TempDir()
	finalPath := filepath.Join(dir, "final.part")
	tempPath := filepath.Join(dir, "temp.part")
	receiver, err := newShardReceiver(
		"upload-2",
		"req-2",
		0,
		generateTestPeerID(t),
		ShardDescriptor{Index: 0, HolderPeerID: generateTestPeerID(t).String(), Size: 3, DigestAlgo: digestAlgoSHA256, Digest: HashShard([]byte("abc"))},
		finalPath,
		tempPath,
	)
	if err != nil {
		t.Fatalf("new shard receiver: %v", err)
	}

	receiver.handleChunk(shardChunkFrame{UploadID: "upload-2", RequestID: "req-2", ShardIndex: 0, Offset: 1, Data: []byte("abc")})
	_, _, err, completed := receiver.result()
	if err == nil || completed {
		t.Fatal("expected offset mismatch failure")
	}

	receiver2, err := newShardReceiver(
		"upload-3",
		"req-3",
		0,
		generateTestPeerID(t),
		ShardDescriptor{Index: 0, HolderPeerID: generateTestPeerID(t).String(), Size: 4, DigestAlgo: digestAlgoSHA256, Digest: HashShard([]byte("abcd"))},
		filepath.Join(dir, "final2.part"),
		filepath.Join(dir, "temp2.part"),
	)
	if err != nil {
		t.Fatalf("new shard receiver 2: %v", err)
	}
	receiver2.handleChunk(shardChunkFrame{UploadID: "upload-3", RequestID: "req-3", ShardIndex: 0, Offset: 0, Data: []byte("ab")})
	receiver2.handleEnd(shardEndFrame{UploadID: "upload-3", RequestID: "req-3", ShardIndex: 0, TotalBytes: 3})
	_, _, err, _ = receiver2.result()
	if err == nil {
		t.Fatal("expected total bytes or digest failure")
	}
}

func TestManagerBeginAndEndDownloadRejectDuplicateID(t *testing.T) {
	manager := &Manager{active: make(map[string]struct{})}
	if err := manager.beginDownload("download-1"); err != nil {
		t.Fatalf("begin download: %v", err)
	}
	if err := manager.beginDownload("download-1"); err == nil {
		t.Fatal("expected duplicate download rejection")
	}
	manager.endDownload("download-1")
	if err := manager.beginDownload("download-1"); err != nil {
		t.Fatalf("begin download after end: %v", err)
	}
}

func TestNewShardReceiverRejectsInvalidTempPath(t *testing.T) {
	_, err := newShardReceiver(
		"upload-4",
		"req-4",
		0,
		generateTestPeerID(t),
		ShardDescriptor{Index: 0, HolderPeerID: generateTestPeerID(t).String(), Size: 1, DigestAlgo: digestAlgoSHA256, Digest: HashShard([]byte("a"))},
		filepath.Join(t.TempDir(), "final.part"),
		filepath.Join(t.TempDir(), "missing", "temp.part"),
	)
	if err == nil {
		t.Fatal("expected temp file creation failure")
	}
}

func generateTestPeerID(t *testing.T) peer.ID {
	t.Helper()
	_, pub, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	peerID, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("derive peer id: %v", err)
	}
	return peerID
}
