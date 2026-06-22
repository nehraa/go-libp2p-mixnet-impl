package download

import (
	"context"
	"io"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// ReconstructionMode controls final output behavior after shard downloads.
type ReconstructionMode string

const (
	// ReconstructionModeStrict requires all expected shard indexes.
	ReconstructionModeStrict ReconstructionMode = "strict"
	// ReconstructionModeThreshold requires K valid shards and uses an injected reconstructor.
	ReconstructionModeThreshold ReconstructionMode = "threshold"
	// ReconstructionModeBestEffort reconstructs from whatever valid shards are available.
	ReconstructionModeBestEffort ReconstructionMode = "best_effort"
)

// ShardSource binds one shard index to one holder peer.
type ShardSource struct {
	ShardIndex int
	Holder     peer.AddrInfo
}

// DownloadRequest contains one download/reconstruction operation.
type DownloadRequest struct {
	UploadID       string
	Sources        []ShardSource
	SignedManifest SignedShardManifest

	Mode      ReconstructionMode
	Threshold int

	// Optional explicit output path.
	OutputPath string
}

// ShardDownloadResult captures outcome for one requested shard.
type ShardDownloadResult struct {
	Index         int       `json:"index"`
	PeerID        string    `json:"peer_id"`
	Bytes         int64     `json:"bytes"`
	Path          string    `json:"path"`
	Status        string    `json:"status"`
	HashValid     bool      `json:"hash_valid"`
	Error         string    `json:"error,omitempty"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`
	RequestID     string    `json:"request_id"`
	Attempts      int       `json:"attempts"`
	Reconstructed bool      `json:"reconstructed"`
}

// DownloadResult captures the final manager output.
type DownloadResult struct {
	UploadID      string                `json:"upload_id"`
	Mode          ReconstructionMode    `json:"mode"`
	OutputPath    string                `json:"output_path"`
	ShardResults  []ShardDownloadResult `json:"shard_results"`
	MissingShards []int                 `json:"missing_shards,omitempty"`
	InvalidShards []int                 `json:"invalid_shards,omitempty"`
	StartedAt     time.Time             `json:"started_at"`
	FinishedAt    time.Time             `json:"finished_at"`
}

// ShardManifest describes immutable shard integrity metadata for one upload.
type ShardManifest struct {
	Version           int               `json:"version"`
	UploadID          string            `json:"upload_id"`
	TotalShards       int               `json:"total_shards"`
	UploaderPeerID    string            `json:"uploader_peer_id"`
	UploaderPublicKey []byte            `json:"uploader_public_key"`
	CreatedAt         time.Time         `json:"created_at"`
	Shards            []ShardDescriptor `json:"shards"`
}

// ShardDescriptor identifies one expected shard.
type ShardDescriptor struct {
	Index        int    `json:"index"`
	HolderPeerID string `json:"holder_peer_id"`
	Size         int64  `json:"size"`
	DigestAlgo   string `json:"digest_algo"`
	Digest       []byte `json:"digest"`
}

// SignedShardManifest wraps ShardManifest and its uploader signature.
type SignedShardManifest struct {
	Manifest  ShardManifest `json:"manifest"`
	Signature []byte        `json:"signature"`
}

// DownloadedShard references one verified shard on local storage.
type DownloadedShard struct {
	Index int
	Path  string
	Bytes int64
}

// ThresholdReconstructor reconstructs output from partial shard sets.
type ThresholdReconstructor interface {
	Reconstruct(ctx context.Context, shards []DownloadedShard, threshold int, total int, output io.Writer) error
}

// ShardReadResult describes a holder-provided shard stream.
type ShardReadResult struct {
	Reader io.ReadCloser
	Size   int64
}

// ShardProvider opens holder-side shard data for a request.
type ShardProvider interface {
	OpenShard(ctx context.Context, uploadID string, shardIndex int) (ShardReadResult, error)
}
