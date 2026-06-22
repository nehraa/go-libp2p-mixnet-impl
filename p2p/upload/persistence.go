package upload

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"
)

type atomicFile interface {
	Write([]byte) (int, error)
	Chmod(os.FileMode) error
	Sync() error
	Close() error
	Name() string
}

var createTempFile = func(dir string, pattern string) (atomicFile, error) {
	return os.CreateTemp(dir, pattern)
}

var renamePath = os.Rename

var openDir = os.Open

// FileSenderManifestStore writes sender-side manifest files to disk.
type FileSenderManifestStore struct {
	root string
}

// NewFileSenderManifestStore returns a sender manifest store rooted at root.
func NewFileSenderManifestStore(root string) *FileSenderManifestStore {
	return &FileSenderManifestStore{root: filepath.Clean(root)}
}

// SaveSenderManifest persists both the full sender manifest and a node-id snapshot.
func (s *FileSenderManifestStore) SaveSenderManifest(
	ctx context.Context,
	manifest *SenderManifest,
) (string, string, error) {
	if err := contextErr(ctx); err != nil {
		return "", "", err
	}
	if manifest == nil {
		return "", "", fmt.Errorf("%w: sender manifest is nil", ErrInvalidRequest)
	}
	uploadID, err := normalizeUploadID(manifest.UploadID)
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(s.root, 0o755); err != nil {
		return "", "", fmt.Errorf("create sender manifest root: %w", err)
	}

	manifestPath := filepath.Join(s.root, uploadID+".sender.json")
	if err := writeJSONFile(manifestPath, manifest); err != nil {
		return "", "", err
	}

	peerMap := make(map[int]string, len(manifest.Shards))
	for _, shard := range manifest.Shards {
		peerMap[shard.Index] = shard.PeerID
	}
	nodeIDs := &NodeIDsManifest{
		UploadID:       uploadID,
		ProtocolID:     manifest.ProtocolID,
		PeerIDs:        append([]string(nil), manifest.SelectedPeers...),
		ShardPeerIndex: peerMap,
		CompletedAt:    manifest.FinishedAt,
	}
	nodeIDsPath := filepath.Join(s.root, uploadID+".nodes.json")
	if err := writeJSONFile(nodeIDsPath, nodeIDs); err != nil {
		return "", "", err
	}
	return manifestPath, nodeIDsPath, nil
}

// FileReceiverManifestStore updates a receiver-side per-upload manifest file.
type FileReceiverManifestStore struct {
	root string
	mu   sync.Mutex
}

// NewFileReceiverManifestStore creates a receiver manifest store.
func NewFileReceiverManifestStore(root string) *FileReceiverManifestStore {
	return &FileReceiverManifestStore{root: filepath.Clean(root)}
}

// SaveReceiverShard records one receiver shard write into the upload manifest.
func (s *FileReceiverManifestStore) SaveReceiverShard(
	ctx context.Context,
	manifest ReceiverManifest,
) (string, error) {
	if err := contextErr(ctx); err != nil {
		return "", err
	}
	uploadID, err := normalizeUploadID(manifest.UploadID)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(s.root, uploadID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create receiver upload dir: %w", err)
	}
	path := filepath.Join(dir, "manifest.receiver.json")

	s.mu.Lock()
	defer s.mu.Unlock()

	existing := ReceiverManifest{}
	b, readErr := os.ReadFile(path)
	if readErr == nil {
		if unmarshalErr := json.Unmarshal(b, &existing); unmarshalErr != nil {
			return "", fmt.Errorf("decode receiver manifest: %w", unmarshalErr)
		}
	} else if !os.IsNotExist(readErr) {
		return "", fmt.Errorf("read receiver manifest: %w", readErr)
	}
	if existing.UploadID == "" {
		existing.UploadID = uploadID
		existing.ProtocolID = manifest.ProtocolID
	}
	if manifest.ShardCount > existing.ShardCount {
		existing.ShardCount = manifest.ShardCount
	}

	for _, rec := range manifest.Records {
		existing = mergeReceiverRecord(existing, rec)
	}
	existing.UpdatedAt = time.Now().UTC()
	if err := writeJSONFile(path, &existing); err != nil {
		return "", err
	}
	return path, nil
}

func mergeReceiverRecord(manifest ReceiverManifest, record ReceiverShardRecord) ReceiverManifest {
	replaced := false
	for i := range manifest.Records {
		if manifest.Records[i].ShardIndex == record.ShardIndex {
			manifest.Records[i] = record
			replaced = true
			break
		}
	}
	if !replaced {
		manifest.Records = append(manifest.Records, record)
	}
	sort.Slice(manifest.Records, func(i, j int) bool {
		return manifest.Records[i].ShardIndex < manifest.Records[j].ShardIndex
	})
	return manifest
}

// FileShardStore writes shard bytes to per-upload files.
type FileShardStore struct {
	root      string
	overwrite bool
}

// NewFileShardStore creates a file-based shard writer.
func NewFileShardStore(root string, overwrite bool) *FileShardStore {
	return &FileShardStore{
		root:      filepath.Clean(root),
		overwrite: overwrite,
	}
}

// WriteShard persists one shard.
func (s *FileShardStore) WriteShard(ctx context.Context, req ShardWriteRequest) (ShardWriteResult, error) {
	if err := contextErr(ctx); err != nil {
		return ShardWriteResult{}, err
	}
	uploadID, err := normalizeUploadID(req.UploadID)
	if err != nil {
		return ShardWriteResult{}, err
	}
	if req.ShardIndex < 0 || req.TotalShards <= 0 || req.ShardIndex >= req.TotalShards {
		return ShardWriteResult{}, fmt.Errorf("%w: invalid shard metadata", ErrInvalidRequest)
	}
	dir := filepath.Join(s.root, uploadID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ShardWriteResult{}, fmt.Errorf("create shard dir: %w", err)
	}

	path := filepath.Join(dir, fmt.Sprintf("%06d.part", req.ShardIndex))
	if !s.overwrite {
		if _, statErr := os.Stat(path); statErr == nil {
			return ShardWriteResult{}, fmt.Errorf("%w: shard %d already exists", ErrInvalidRequest, req.ShardIndex)
		} else if !os.IsNotExist(statErr) {
			return ShardWriteResult{}, fmt.Errorf("stat shard file: %w", statErr)
		}
	}
	if err := writeFileAtomically(path, req.Data, 0o644, true); err != nil {
		return ShardWriteResult{}, fmt.Errorf("write shard file: %w", err)
	}
	return ShardWriteResult{
		Path:  path,
		Bytes: len(req.Data),
	}, nil
}

func writeJSONFile(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode json %s: %w", path, err)
	}
	raw = append(raw, '\n')
	if err := writeFileAtomically(path, raw, 0o644, true); err != nil {
		return fmt.Errorf("write json %s: %w", path, err)
	}
	return nil
}

func writeFileAtomically(path string, data []byte, perm os.FileMode, syncWrite bool) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmpFile, err := createTempFile(dir, ".upload-tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()

	cleanup := func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}
	if _, err := tmpFile.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmpFile.Chmod(perm); err != nil {
		cleanup()
		return err
	}
	if syncWrite {
		if err := tmpFile.Sync(); err != nil {
			cleanup()
			return err
		}
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := renamePath(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if syncWrite {
		if err := syncDir(dir); err != nil {
			return err
		}
	}
	return nil
}

func syncDir(dir string) error {
	f, err := openDir(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Sync(); err != nil && runtime.GOOS != "windows" {
		return err
	}
	return nil
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}
