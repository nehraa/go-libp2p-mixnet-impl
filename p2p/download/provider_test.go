package download

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileShardProviderOpenShard(t *testing.T) {
	root := t.TempDir()
	const uploadID = "provider-upload"
	const shardIndex = 3
	data := []byte("provider-data")

	dir := filepath.Join(root, uploadID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, formatShardFile(shardIndex))
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write shard: %v", err)
	}

	provider := NewFileShardProvider(root)
	result, err := provider.OpenShard(context.Background(), uploadID, shardIndex)
	if err != nil {
		t.Fatalf("open shard: %v", err)
	}
	defer result.Reader.Close()
	if result.Size != int64(len(data)) {
		t.Fatalf("unexpected shard size: got=%d want=%d", result.Size, len(data))
	}
}

func TestFileShardProviderOpenShardMissingFile(t *testing.T) {
	provider := NewFileShardProvider(t.TempDir())
	_, err := provider.OpenShard(context.Background(), "missing-upload", 0)
	if err == nil {
		t.Fatal("expected missing shard error")
	}
}

func TestFileShardProviderOpenShardRejectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	provider := NewFileShardProvider(t.TempDir())
	_, err := provider.OpenShard(ctx, "upload", 0)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}
}
