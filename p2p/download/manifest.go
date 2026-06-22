package download

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	manifestVersion  = 1
	digestAlgoSHA256 = "sha256"
)

type canonicalManifest struct {
	Version           int                     `json:"version"`
	UploadID          string                  `json:"upload_id"`
	TotalShards       int                     `json:"total_shards"`
	UploaderPeerID    string                  `json:"uploader_peer_id"`
	UploaderPublicKey []byte                  `json:"uploader_public_key"`
	CreatedAt         time.Time               `json:"created_at"`
	Shards            []canonicalShardSummary `json:"shards"`
}

type canonicalShardSummary struct {
	Index        int    `json:"index"`
	HolderPeerID string `json:"holder_peer_id"`
	Size         int64  `json:"size"`
	DigestAlgo   string `json:"digest_algo"`
	Digest       []byte `json:"digest"`
}

// HashShard returns the SHA-256 digest for shard bytes.
func HashShard(data []byte) []byte {
	sum := sha256.Sum256(data)
	return append([]byte(nil), sum[:]...)
}

// SignManifest signs a canonicalized shard manifest.
func SignManifest(manifest ShardManifest, signer crypto.PrivKey) (SignedShardManifest, error) {
	if signer == nil {
		return SignedShardManifest{}, fmt.Errorf("%w: signer is required", ErrManifestInvalid)
	}
	publicKey := signer.GetPublic()
	publicKeyRaw, err := crypto.MarshalPublicKey(publicKey)
	if err != nil {
		return SignedShardManifest{}, fmt.Errorf("marshal uploader public key: %w", err)
	}
	uploaderPeerID, err := peer.IDFromPublicKey(publicKey)
	if err != nil {
		return SignedShardManifest{}, fmt.Errorf("derive uploader peer id: %w", err)
	}
	manifest.UploaderPublicKey = publicKeyRaw
	manifest.UploaderPeerID = uploaderPeerID.String()

	if manifest.Version == 0 {
		manifest.Version = manifestVersion
	}
	if manifest.CreatedAt.IsZero() {
		manifest.CreatedAt = time.Now().UTC()
	}

	if err := validateManifest(manifest); err != nil {
		return SignedShardManifest{}, err
	}
	payload, err := canonicalManifestBytes(manifest)
	if err != nil {
		return SignedShardManifest{}, err
	}
	sig, err := signer.Sign(payload)
	if err != nil {
		return SignedShardManifest{}, fmt.Errorf("sign shard manifest: %w", err)
	}
	return SignedShardManifest{
		Manifest:  manifest,
		Signature: sig,
	}, nil
}

// VerifySignedManifest validates signature and manifest shape.
func VerifySignedManifest(signed SignedShardManifest) error {
	if len(signed.Signature) == 0 {
		return fmt.Errorf("%w: manifest signature is required", ErrManifestInvalid)
	}
	if err := validateManifest(signed.Manifest); err != nil {
		return err
	}

	pub, err := crypto.UnmarshalPublicKey(signed.Manifest.UploaderPublicKey)
	if err != nil {
		return fmt.Errorf("%w: decode uploader public key: %v", ErrManifestInvalid, err)
	}
	derivedPeerID, err := peer.IDFromPublicKey(pub)
	if err != nil {
		return fmt.Errorf("%w: derive uploader peer id: %v", ErrManifestInvalid, err)
	}
	if derivedPeerID.String() != signed.Manifest.UploaderPeerID {
		return fmt.Errorf(
			"%w: uploader peer id mismatch got=%s want=%s",
			ErrManifestInvalid,
			signed.Manifest.UploaderPeerID,
			derivedPeerID,
		)
	}

	payload, err := canonicalManifestBytes(signed.Manifest)
	if err != nil {
		return err
	}
	ok, err := pub.Verify(payload, signed.Signature)
	if err != nil {
		return fmt.Errorf("%w: verify signature: %v", ErrManifestInvalid, err)
	}
	if !ok {
		return fmt.Errorf("%w: signature invalid", ErrManifestInvalid)
	}
	return nil
}

func validateManifest(manifest ShardManifest) error {
	uploadID, err := normalizeUploadID(manifest.UploadID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrManifestInvalid, err)
	}
	if uploadID != manifest.UploadID {
		return fmt.Errorf("%w: upload id must be normalized", ErrManifestInvalid)
	}
	if manifest.Version != manifestVersion {
		return fmt.Errorf("%w: unsupported manifest version %d", ErrManifestInvalid, manifest.Version)
	}
	if manifest.TotalShards <= 0 {
		return fmt.Errorf("%w: total shards must be positive", ErrManifestInvalid)
	}
	if manifest.UploaderPeerID == "" {
		return fmt.Errorf("%w: uploader peer id is required", ErrManifestInvalid)
	}
	if _, err := peer.Decode(manifest.UploaderPeerID); err != nil {
		return fmt.Errorf("%w: invalid uploader peer id: %v", ErrManifestInvalid, err)
	}
	if len(manifest.UploaderPublicKey) == 0 {
		return fmt.Errorf("%w: uploader public key is required", ErrManifestInvalid)
	}
	if len(manifest.Shards) == 0 {
		return fmt.Errorf("%w: shard descriptors are required", ErrManifestInvalid)
	}
	seen := make(map[int]struct{}, len(manifest.Shards))
	for _, shard := range manifest.Shards {
		if shard.Index < 0 || shard.Index >= manifest.TotalShards {
			return fmt.Errorf("%w: invalid shard index %d", ErrManifestInvalid, shard.Index)
		}
		if _, ok := seen[shard.Index]; ok {
			return fmt.Errorf("%w: duplicate shard index %d", ErrManifestInvalid, shard.Index)
		}
		seen[shard.Index] = struct{}{}
		if shard.HolderPeerID == "" {
			return fmt.Errorf("%w: holder peer id required for shard %d", ErrManifestInvalid, shard.Index)
		}
		if _, err := peer.Decode(shard.HolderPeerID); err != nil {
			return fmt.Errorf("%w: invalid holder peer id for shard %d: %v", ErrManifestInvalid, shard.Index, err)
		}
		if shard.Size < 0 {
			return fmt.Errorf("%w: invalid shard size for index %d", ErrManifestInvalid, shard.Index)
		}
		if shard.DigestAlgo != digestAlgoSHA256 {
			return fmt.Errorf("%w: unsupported digest algorithm %q", ErrManifestInvalid, shard.DigestAlgo)
		}
		if len(shard.Digest) != sha256.Size {
			return fmt.Errorf("%w: invalid digest size for shard %d", ErrManifestInvalid, shard.Index)
		}
	}
	return nil
}

func canonicalManifestBytes(manifest ShardManifest) ([]byte, error) {
	shards := append([]ShardDescriptor(nil), manifest.Shards...)
	sort.Slice(shards, func(i, j int) bool {
		return shards[i].Index < shards[j].Index
	})

	canonical := canonicalManifest{
		Version:           manifest.Version,
		UploadID:          manifest.UploadID,
		TotalShards:       manifest.TotalShards,
		UploaderPeerID:    manifest.UploaderPeerID,
		UploaderPublicKey: append([]byte(nil), manifest.UploaderPublicKey...),
		CreatedAt:         manifest.CreatedAt.UTC(),
		Shards:            make([]canonicalShardSummary, 0, len(shards)),
	}
	for _, shard := range shards {
		canonical.Shards = append(canonical.Shards, canonicalShardSummary{
			Index:        shard.Index,
			HolderPeerID: shard.HolderPeerID,
			Size:         shard.Size,
			DigestAlgo:   shard.DigestAlgo,
			Digest:       append([]byte(nil), shard.Digest...),
		})
	}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical manifest: %w", err)
	}
	return raw, nil
}

func descriptorByIndex(manifest ShardManifest) map[int]ShardDescriptor {
	out := make(map[int]ShardDescriptor, len(manifest.Shards))
	for _, shard := range manifest.Shards {
		out[shard.Index] = shard
	}
	return out
}
