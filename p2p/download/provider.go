package download

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// FileShardProvider opens shard files from disk.
type FileShardProvider struct {
	root string
}

// NewFileShardProvider creates a file-backed shard provider rooted at root.
func NewFileShardProvider(root string) *FileShardProvider {
	return &FileShardProvider{root: filepath.Clean(root)}
}

// OpenShard opens one shard file by upload id and shard index.
func (p *FileShardProvider) OpenShard(ctx context.Context, uploadID string, shardIndex int) (ShardReadResult, error) {
	if err := contextErr(ctx); err != nil {
		return ShardReadResult{}, err
	}
	if shardIndex < 0 {
		return ShardReadResult{}, fmt.Errorf("%w: shard index must be non-negative", ErrInvalidRequest)
	}
	normalizedUploadID, err := normalizeUploadID(uploadID)
	if err != nil {
		return ShardReadResult{}, err
	}
	path := filepath.Join(p.root, normalizedUploadID, formatShardFile(shardIndex))
	file, err := os.Open(path)
	if err != nil {
		return ShardReadResult{}, fmt.Errorf("open shard %d: %w", shardIndex, err)
	}
	stat, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return ShardReadResult{}, fmt.Errorf("stat shard %d: %w", shardIndex, err)
	}
	return ShardReadResult{
		Reader: file,
		Size:   stat.Size(),
	}, nil
}

func formatShardFile(index int) string {
	return fmt.Sprintf("%06d.part", index)
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}
