package download

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

func TestSignAndVerifyManifest(t *testing.T) {
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	_, holderPubA, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("generate holder key a: %v", err)
	}
	holderPubAID, err := peer.IDFromPublicKey(holderPubA)
	if err != nil {
		t.Fatalf("holder peer id a: %v", err)
	}
	_, holderPubB, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("generate holder key b: %v", err)
	}
	holderPubBID, err := peer.IDFromPublicKey(holderPubB)
	if err != nil {
		t.Fatalf("holder peer id b: %v", err)
	}

	manifest := ShardManifest{
		Version:     manifestVersion,
		UploadID:    "upload-1",
		TotalShards: 2,
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
		Shards: []ShardDescriptor{
			{Index: 1, HolderPeerID: holderPubBID.String(), Size: 3, DigestAlgo: digestAlgoSHA256, Digest: HashShard([]byte("bbb"))},
			{Index: 0, HolderPeerID: holderPubAID.String(), Size: 3, DigestAlgo: digestAlgoSHA256, Digest: HashShard([]byte("aaa"))},
		},
	}

	signed, err := SignManifest(manifest, priv)
	if err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	if err := VerifySignedManifest(signed); err != nil {
		t.Fatalf("verify manifest: %v", err)
	}

	tampered := signed
	tampered.Manifest.Shards[0].Digest = bytes.Repeat([]byte{0xAA}, 32)
	if err := VerifySignedManifest(tampered); err == nil {
		t.Fatal("expected verify failure for tampered manifest")
	}
}

func TestVerifySignedManifestRejectsPeerMismatch(t *testing.T) {
	priv, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_, holderPub, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatalf("generate holder key: %v", err)
	}
	holderID, err := peer.IDFromPublicKey(holderPub)
	if err != nil {
		t.Fatalf("holder peer id: %v", err)
	}

	manifest := ShardManifest{
		Version:     manifestVersion,
		UploadID:    "upload-2",
		TotalShards: 1,
		CreatedAt:   time.Now().UTC().Truncate(time.Second),
		Shards: []ShardDescriptor{
			{Index: 0, HolderPeerID: holderID.String(), Size: 3, DigestAlgo: digestAlgoSHA256, Digest: HashShard([]byte("aaa"))},
		},
	}

	signed, err := SignManifest(manifest, priv)
	if err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	signed.Manifest.UploaderPeerID = "12D3KooWInvalidPeerID"
	if err := VerifySignedManifest(signed); err == nil {
		t.Fatal("expected peer mismatch validation failure")
	}
}

func TestSignManifestRejectsNilSigner(t *testing.T) {
	_, err := SignManifest(ShardManifest{
		Version:     manifestVersion,
		UploadID:    "nil-signer",
		TotalShards: 1,
		CreatedAt:   time.Now().UTC(),
		Shards: []ShardDescriptor{
			{Index: 0, HolderPeerID: generateTestPeerID(t).String(), Size: 1, DigestAlgo: digestAlgoSHA256, Digest: HashShard([]byte("a"))},
		},
	}, nil)
	if err == nil {
		t.Fatal("expected nil signer error")
	}
}

func TestVerifySignedManifestRejectsMissingSignature(t *testing.T) {
	signed := signTestManifest(t, "missing-sig", []ShardDescriptor{
		{Index: 0, HolderPeerID: generateTestPeerID(t).String(), Size: 1, DigestAlgo: digestAlgoSHA256, Digest: HashShard([]byte("a"))},
	})
	signed.Signature = nil
	if err := VerifySignedManifest(signed); err == nil {
		t.Fatal("expected missing signature validation failure")
	}
}

func TestVerifySignedManifestRejectsBadPublicKey(t *testing.T) {
	signed := signTestManifest(t, "bad-pubkey", []ShardDescriptor{
		{Index: 0, HolderPeerID: generateTestPeerID(t).String(), Size: 1, DigestAlgo: digestAlgoSHA256, Digest: HashShard([]byte("a"))},
	})
	signed.Manifest.UploaderPublicKey = []byte{0x01, 0x02, 0x03}
	if err := VerifySignedManifest(signed); err == nil {
		t.Fatal("expected public key decode failure")
	}
}

func TestValidateManifestRejectsInvalidFields(t *testing.T) {
	base := signTestManifest(t, "validate-manifest", []ShardDescriptor{
		{Index: 0, HolderPeerID: generateTestPeerID(t).String(), Size: 1, DigestAlgo: digestAlgoSHA256, Digest: HashShard([]byte("a"))},
		{Index: 1, HolderPeerID: generateTestPeerID(t).String(), Size: 1, DigestAlgo: digestAlgoSHA256, Digest: HashShard([]byte("b"))},
	}).Manifest

	tests := []struct {
		name   string
		mutate func(*ShardManifest)
	}{
		{
			name:   "bad version",
			mutate: func(m *ShardManifest) { m.Version = manifestVersion + 1 },
		},
		{
			name:   "missing uploader peer id",
			mutate: func(m *ShardManifest) { m.UploaderPeerID = "" },
		},
		{
			name:   "invalid uploader peer id",
			mutate: func(m *ShardManifest) { m.UploaderPeerID = "not-a-peer" },
		},
		{
			name:   "missing uploader public key",
			mutate: func(m *ShardManifest) { m.UploaderPublicKey = nil },
		},
		{
			name:   "zero total shards",
			mutate: func(m *ShardManifest) { m.TotalShards = 0 },
		},
		{
			name:   "duplicate shard index",
			mutate: func(m *ShardManifest) { m.Shards[1].Index = m.Shards[0].Index },
		},
		{
			name:   "invalid holder peer id",
			mutate: func(m *ShardManifest) { m.Shards[0].HolderPeerID = "bad-peer" },
		},
		{
			name:   "unsupported digest algo",
			mutate: func(m *ShardManifest) { m.Shards[0].DigestAlgo = "sha1" },
		},
		{
			name:   "wrong digest size",
			mutate: func(m *ShardManifest) { m.Shards[0].Digest = []byte{1, 2} },
		},
		{
			name:   "negative shard size",
			mutate: func(m *ShardManifest) { m.Shards[0].Size = -1 },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifest := base
			tc.mutate(&manifest)
			if err := validateManifest(manifest); err == nil {
				t.Fatalf("expected validation failure for %s", tc.name)
			}
		})
	}
}
