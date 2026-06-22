package upload

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

// SuccessMode controls when a shard send is considered successful.
type SuccessMode string

const (
	// SuccessModeAckOnPersist marks success only after receiver durability ACK.
	SuccessModeAckOnPersist SuccessMode = "ack_on_persist"
	// SuccessModeWriteAccepted marks success after local stream write.
	SuccessModeWriteAccepted SuccessMode = "write_accepted"
)

// UploadRequest describes one sender-side upload operation.
type UploadRequest struct {
	UploadID string

	// Buffer holds pre-sharded payload data.
	// The sender uses zero-copy views over this buffer, so it must remain valid
	// and unmodified until Upload returns.
	Buffer []byte

	// Delimiter separates shards in Buffer.
	Delimiter []byte

	// ExpectedShardCount must match the discovered shard count when greater than zero.
	ExpectedShardCount int

	// TargetPeers bypasses discovery when provided.
	TargetPeers []peer.AddrInfo

	// Optional request override.
	SuccessMode SuccessMode
}

// ShardView points to one shard range inside the original caller buffer.
// Data is a view onto the source buffer, not a deep copy.
type ShardView struct {
	Index int
	Start int
	End   int
	Data  []byte
}

// ShardUploadResult captures sender-side outcome for one shard.
type ShardUploadResult struct {
	Index      int       `json:"index"`
	PeerID     string    `json:"peer_id"`
	Start      int       `json:"start"`
	End        int       `json:"end"`
	Bytes      int       `json:"bytes"`
	Status     string    `json:"status"`
	Acked      bool      `json:"acked"`
	Error      string    `json:"error,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}

// UploadResult is the top-level sender upload response.
type UploadResult struct {
	UploadID      string              `json:"upload_id"`
	ProtocolID    string              `json:"protocol_id"`
	SuccessMode   SuccessMode         `json:"success_mode"`
	SelectedPeers []string            `json:"selected_peers"`
	ShardResults  []ShardUploadResult `json:"shard_results"`
	ManifestPath  string              `json:"manifest_path"`
	NodeIDsPath   string              `json:"node_ids_path"`
	StartedAt     time.Time           `json:"started_at"`
	FinishedAt    time.Time           `json:"finished_at"`
}

// SenderManifest persists sender-side upload metadata.
type SenderManifest struct {
	UploadID      string              `json:"upload_id"`
	ProtocolID    string              `json:"protocol_id"`
	SuccessMode   SuccessMode         `json:"success_mode"`
	SelectedPeers []string            `json:"selected_peers"`
	Shards        []ShardUploadResult `json:"shards"`
	StartedAt     time.Time           `json:"started_at"`
	FinishedAt    time.Time           `json:"finished_at"`
}

// NodeIDsManifest is a minimal peer-id snapshot persisted after upload completion.
type NodeIDsManifest struct {
	UploadID       string            `json:"upload_id"`
	ProtocolID     string            `json:"protocol_id"`
	PeerIDs        []string          `json:"peer_ids"`
	ShardPeerIndex map[int]string    `json:"shard_peer_index"`
	CompletedAt    time.Time         `json:"completed_at"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// ReceiverShardRecord stores one received shard entry.
type ReceiverShardRecord struct {
	ShardIndex   int       `json:"shard_index"`
	TotalShards  int       `json:"total_shards"`
	Path         string    `json:"path"`
	Bytes        int       `json:"bytes"`
	SenderPeerID string    `json:"sender_peer_id"`
	ReceivedAt   time.Time `json:"received_at"`
}

// ReceiverManifest persists receiver-side shard write metadata.
type ReceiverManifest struct {
	UploadID   string                `json:"upload_id"`
	ProtocolID string                `json:"protocol_id"`
	ShardCount int                   `json:"shard_count"`
	Records    []ReceiverShardRecord `json:"records"`
	UpdatedAt  time.Time             `json:"updated_at"`
}

// PeerResolveRequest contains input for peer resolution.
type PeerResolveRequest struct {
	Required   int
	Explicit   []peer.AddrInfo
	LocalPeer  peer.ID
	ProtocolID protocol.ID
}

// PeerResolver resolves peers for one upload.
type PeerResolver interface {
	ResolvePeers(ctx context.Context, req PeerResolveRequest) ([]peer.AddrInfo, error)
}

// SenderManifestStore persists sender manifest outputs.
type SenderManifestStore interface {
	SaveSenderManifest(ctx context.Context, manifest *SenderManifest) (manifestPath string, nodeIDsPath string, err error)
}

// ReceiverManifestStore persists receiver shard manifests.
type ReceiverManifestStore interface {
	SaveReceiverShard(ctx context.Context, manifest ReceiverManifest) (manifestPath string, err error)
}

// ShardWriteRequest defines one receiver-side shard persistence action.
type ShardWriteRequest struct {
	UploadID    string
	ShardIndex  int
	TotalShards int
	Data        []byte
}

// ShardWriteResult contains output of one receiver-side shard persistence action.
type ShardWriteResult struct {
	Path  string
	Bytes int
}

// ShardStore writes shard data to persistence.
type ShardStore interface {
	WriteShard(ctx context.Context, req ShardWriteRequest) (ShardWriteResult, error)
}

// ShardValidationRequest describes one receiver-side shard validation call.
type ShardValidationRequest struct {
	UploadID     string
	SenderPeerID string
	ShardIndex   int
	TotalShards  int
	Data         []byte
}

// ShardValidationPolicy decides whether a shard is accepted before persistence.
type ShardValidationPolicy interface {
	ValidateShard(ctx context.Context, req ShardValidationRequest) error
}
