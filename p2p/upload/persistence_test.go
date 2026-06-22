package upload

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveSenderManifestRejectsNilAndCanceledContext(t *testing.T) {
	store := NewFileSenderManifestStore(t.TempDir())

	if _, _, err := store.SaveSenderManifest(context.Background(), nil); err == nil {
		t.Fatal("expected nil manifest error")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := store.SaveSenderManifest(ctx, &SenderManifest{UploadID: "upload-1"}); err == nil {
		t.Fatal("expected canceled context error")
	}
}

func TestSaveSenderManifestRejectsInvalidUploadID(t *testing.T) {
	store := NewFileSenderManifestStore(t.TempDir())
	_, _, err := store.SaveSenderManifest(context.Background(), &SenderManifest{UploadID: "   "})
	if err == nil {
		t.Fatal("expected invalid upload id error")
	}
}

func TestSaveSenderManifestFailsWhenRootIsFile(t *testing.T) {
	rootFile, err := os.CreateTemp(t.TempDir(), "root-file-*")
	if err != nil {
		t.Fatalf("create root file: %v", err)
	}
	defer rootFile.Close()

	store := NewFileSenderManifestStore(rootFile.Name())
	_, _, err = store.SaveSenderManifest(context.Background(), &SenderManifest{UploadID: "upload-1"})
	if err == nil {
		t.Fatal("expected mkdir error")
	}
}

func TestSaveSenderManifestFailsWhenNodeIDsWriteFails(t *testing.T) {
	originalCreateTemp := createTempFile
	defer func() {
		createTempFile = originalCreateTemp
	}()

	calls := 0
	createTempFile = func(dir, pattern string) (atomicFile, error) {
		calls++
		if calls == 2 {
			return nil, errors.New("node ids failed")
		}
		file, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		return &atomicFileBehavior{file: file}, nil
	}

	store := NewFileSenderManifestStore(t.TempDir())
	_, _, err := store.SaveSenderManifest(context.Background(), &SenderManifest{
		UploadID:     "upload-1",
		ProtocolID:   "/upload/test",
		SelectedPeers: []string{"peer-1"},
		Shards:       []ShardUploadResult{{Index: 0}},
	})
	if err == nil || !strings.Contains(err.Error(), "node ids failed") {
		t.Fatalf("expected node ids failure, got %v", err)
	}
}

func TestSaveReceiverShardRejectsCanceledContextAndInvalidUploadID(t *testing.T) {
	store := NewFileReceiverManifestStore(t.TempDir())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.SaveReceiverShard(ctx, ReceiverManifest{UploadID: "upload-1"}); err == nil {
		t.Fatal("expected canceled context error")
	}

	if _, err := store.SaveReceiverShard(context.Background(), ReceiverManifest{UploadID: "   "}); err == nil {
		t.Fatal("expected invalid upload id error")
	}
}

func TestSaveReceiverShardRejectsInvalidExistingManifest(t *testing.T) {
	root := t.TempDir()
	uploadID := "upload-1"
	dir := filepath.Join(root, uploadID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.receiver.json"), []byte("{"), 0o644); err != nil {
		t.Fatalf("seed invalid manifest: %v", err)
	}

	store := NewFileReceiverManifestStore(root)
	_, err := store.SaveReceiverShard(context.Background(), ReceiverManifest{UploadID: uploadID})
	if err == nil {
		t.Fatal("expected invalid manifest decode error")
	}
}

func TestSaveReceiverShardReturnsManifestWriteError(t *testing.T) {
	originalCreateTemp := createTempFile
	defer func() {
		createTempFile = originalCreateTemp
	}()
	createTempFile = func(string, string) (atomicFile, error) {
		return nil, errors.New("manifest temp failed")
	}

	store := NewFileReceiverManifestStore(t.TempDir())
	_, err := store.SaveReceiverShard(context.Background(), ReceiverManifest{
		UploadID:   "upload-1",
		ProtocolID: "/upload/test",
		Records: []ReceiverShardRecord{
			{ShardIndex: 0, TotalShards: 1, Path: "shard", Bytes: 1, SenderPeerID: "peer"},
		},
	})
	if err != nil {
		if !strings.Contains(err.Error(), "manifest temp failed") {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	t.Fatal("expected manifest write error")
}

func TestMergeReceiverRecordReplacesAndSorts(t *testing.T) {
	manifest := ReceiverManifest{
		Records: []ReceiverShardRecord{
			{ShardIndex: 2, Path: "two"},
			{ShardIndex: 4, Path: "four"},
		},
	}

	got := mergeReceiverRecord(manifest, ReceiverShardRecord{ShardIndex: 2, Path: "updated"})
	if len(got.Records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(got.Records))
	}
	if got.Records[0].ShardIndex != 2 || got.Records[0].Path != "updated" {
		t.Fatalf("unexpected first record: %+v", got.Records[0])
	}

	got = mergeReceiverRecord(got, ReceiverShardRecord{ShardIndex: 1, Path: "one"})
	if got.Records[0].ShardIndex != 1 || got.Records[2].ShardIndex != 4 {
		t.Fatalf("records not sorted: %+v", got.Records)
	}
}

func TestWriteShardRejectsCanceledContextAndExistingFile(t *testing.T) {
	store := NewFileShardStore(t.TempDir(), false)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.WriteShard(ctx, ShardWriteRequest{UploadID: "upload-1", ShardIndex: 0, TotalShards: 1, Data: []byte("x")}); err == nil {
		t.Fatal("expected canceled context error")
	}

	root := t.TempDir()
	uploadID := "upload-2"
	existingPath := filepath.Join(root, uploadID, formatShardFile(0))
	if err := os.MkdirAll(filepath.Dir(existingPath), 0o755); err != nil {
		t.Fatalf("create shard dir: %v", err)
	}
	if err := os.WriteFile(existingPath, []byte("exists"), 0o644); err != nil {
		t.Fatalf("seed shard file: %v", err)
	}
	existingStore := NewFileShardStore(root, false)
	_, err := existingStore.WriteShard(context.Background(), ShardWriteRequest{
		UploadID:    uploadID,
		ShardIndex:  0,
		TotalShards: 1,
		Data:        []byte("new"),
	})
	if err == nil {
		t.Fatal("expected existing shard error")
	}
}

func TestWriteShardRejectsInvalidMetadataAndRootFile(t *testing.T) {
	store := NewFileShardStore(t.TempDir(), false)
	_, err := store.WriteShard(context.Background(), ShardWriteRequest{UploadID: "upload-1", ShardIndex: -1, TotalShards: 1, Data: []byte("x")})
	if err == nil {
		t.Fatal("expected invalid metadata error")
	}

	rootFile, err := os.CreateTemp(t.TempDir(), "root-file-*")
	if err != nil {
		t.Fatalf("create root file: %v", err)
	}
	defer rootFile.Close()

	rootStore := NewFileShardStore(rootFile.Name(), false)
	_, err = rootStore.WriteShard(context.Background(), ShardWriteRequest{UploadID: "upload-1", ShardIndex: 0, TotalShards: 1, Data: []byte("x")})
	if err == nil {
		t.Fatal("expected mkdir error")
	}
}

func TestWriteJSONFileRejectsMarshalError(t *testing.T) {
	target := filepath.Join(t.TempDir(), "out.json")
	if err := writeJSONFile(target, marshalErrorValue{}); err == nil {
		t.Fatal("expected marshal error")
	}
}

func TestWriteFileAtomicallyExercisesFailureBranches(t *testing.T) {
	originalCreateTemp := createTempFile
	originalRename := renamePath
	originalOpen := openDir
	defer func() {
		createTempFile = originalCreateTemp
		renamePath = originalRename
		openDir = originalOpen
	}()

	dir := t.TempDir()
	target := filepath.Join(dir, "out.txt")
	cases := []struct {
		name    string
		setup   func(*atomicFileBehavior)
		wantErr string
	}{
		{
			name: "write",
			setup: func(b *atomicFileBehavior) { b.writeErr = errors.New("write failed") },
			wantErr: "write failed",
		},
		{
			name: "chmod",
			setup: func(b *atomicFileBehavior) { b.chmodErr = errors.New("chmod failed") },
			wantErr: "chmod failed",
		},
		{
			name: "sync",
			setup: func(b *atomicFileBehavior) { b.syncErr = errors.New("sync failed") },
			wantErr: "sync failed",
		},
		{
			name: "close",
			setup: func(b *atomicFileBehavior) { b.closeErr = errors.New("close failed") },
			wantErr: "close failed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			createTempFile = originalCreateTemp
			renamePath = originalRename
			openDir = originalOpen
			createTempFile = func(dir, pattern string) (atomicFile, error) {
				file, err := os.CreateTemp(dir, pattern)
				if err != nil {
					return nil, err
				}
				behavior := &atomicFileBehavior{file: file}
				tc.setup(behavior)
				return behavior, nil
			}
			if err := writeFileAtomically(target, []byte("payload"), 0o644, true); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}

	t.Run("create-temp", func(t *testing.T) {
		createTempFile = originalCreateTemp
		renamePath = originalRename
		openDir = originalOpen
		createTempFile = func(string, string) (atomicFile, error) {
			return nil, errors.New("create temp failed")
		}
		if err := writeFileAtomically(target, []byte("payload"), 0o644, true); err == nil || !strings.Contains(err.Error(), "create temp failed") {
			t.Fatalf("expected create temp error, got %v", err)
		}
	})

	t.Run("rename", func(t *testing.T) {
		createTempFile = originalCreateTemp
		renamePath = originalRename
		openDir = originalOpen
		createTempFile = func(dir, pattern string) (atomicFile, error) {
			file, err := os.CreateTemp(dir, pattern)
			if err != nil {
				return nil, err
			}
			return &atomicFileBehavior{file: file}, nil
		}
		renamePath = func(string, string) error { return errors.New("rename failed") }
		if err := writeFileAtomically(target, []byte("payload"), 0o644, true); err == nil || !strings.Contains(err.Error(), "rename failed") {
			t.Fatalf("expected rename error, got %v", err)
		}
	})

	t.Run("sync-dir", func(t *testing.T) {
		createTempFile = originalCreateTemp
		renamePath = originalRename
		openDir = originalOpen
		createTempFile = func(dir, pattern string) (atomicFile, error) {
			file, err := os.CreateTemp(dir, pattern)
			if err != nil {
				return nil, err
			}
			return &atomicFileBehavior{file: file}, nil
		}
		renamePath = os.Rename
		openDir = func(string) (*os.File, error) {
			return nil, errors.New("open dir failed")
		}
		if err := writeFileAtomically(target, []byte("payload"), 0o644, true); err == nil || !strings.Contains(err.Error(), "open dir failed") {
			t.Fatalf("expected sync dir error, got %v", err)
		}
	})
}

func TestWriteFileAtomicallySkipsSyncWhenDisabled(t *testing.T) {
	target := filepath.Join(t.TempDir(), "out.txt")
	if err := writeFileAtomically(target, []byte("payload"), 0o644, false); err != nil {
		t.Fatalf("write file without sync: %v", err)
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	if string(raw) != "payload" {
		t.Fatalf("unexpected file contents: %q", string(raw))
	}
}

func TestSyncDirReturnsSyncError(t *testing.T) {
	originalOpen := openDir
	defer func() {
		openDir = originalOpen
	}()

	openDir = func(dir string) (*os.File, error) {
		f, err := os.CreateTemp(dir, "sync-*")
		if err != nil {
			return nil, err
		}
		_ = f.Close()
		return f, nil
	}

	if err := syncDir(t.TempDir()); err == nil {
		t.Fatal("expected sync error from closed file")
	}
}

func TestContextErrHandlesNilAndCanceled(t *testing.T) {
	if err := contextErr(nil); err != nil {
		t.Fatalf("expected nil context error, got %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := contextErr(ctx); err == nil {
		t.Fatal("expected canceled context error")
	}
}

type marshalErrorValue struct{}

func (marshalErrorValue) MarshalJSON() ([]byte, error) {
	return nil, errors.New("marshal failed")
}

type atomicFileBehavior struct {
	file     *os.File
	writeErr error
	chmodErr error
	syncErr  error
	closeErr error
}

func (f *atomicFileBehavior) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return f.file.Write(p)
}

func (f *atomicFileBehavior) Chmod(mode os.FileMode) error {
	if f.chmodErr != nil {
		return f.chmodErr
	}
	return f.file.Chmod(mode)
}

func (f *atomicFileBehavior) Sync() error {
	if f.syncErr != nil {
		return f.syncErr
	}
	return f.file.Sync()
}

func (f *atomicFileBehavior) Close() error {
	if f.closeErr != nil {
		return f.closeErr
	}
	return f.file.Close()
}

func (f *atomicFileBehavior) Name() string {
	return f.file.Name()
}
