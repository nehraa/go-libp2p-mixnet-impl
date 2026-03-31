package mixnet

import (
	"bytes"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/mixnet/circuit"
)

func BenchmarkBuildSessionDataFrameControlPrefix(b *testing.B) {
	baseID := "bench-session"

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		prefix, err := buildSessionDataFrameControlPrefix(baseID, true, uint64(i), 3, 7, 16)
		if err != nil {
			b.Fatalf("buildSessionDataFrameControlPrefix() error = %v", err)
		}
		if len(prefix) == 0 {
			b.Fatal("expected non-empty prefix")
		}
	}
}

func BenchmarkEncodePrivacyShard(b *testing.B) {
	payload := bytes.Repeat([]byte("mixnet-privacy-shard-"), 128)
	header := PrivacyShardHeader{
		SessionID:   []byte("bench-session-id"),
		ShardIndex:  2,
		TotalShards: 7,
		HasKeys:     true,
		KeyData:     bytes.Repeat([]byte{0xAB}, 48),
		AuthTag:     bytes.Repeat([]byte{0xCD}, 16),
	}
	paddingCfg := &PrivacyPaddingConfig{
		Enabled:  true,
		MinBytes: 16,
		MaxBytes: 16,
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		encoded, err := EncodePrivacyShard(payload, header, paddingCfg)
		if err != nil {
			b.Fatalf("EncodePrivacyShard() error = %v", err)
		}
		if len(encoded) == 0 {
			b.Fatal("expected encoded shard bytes")
		}
	}
}

func BenchmarkEncryptOnion(b *testing.B) {
	c := &circuit.Circuit{
		ID: "bench-circuit",
		Peers: []peer.ID{
			peer.ID("peer-a"),
			peer.ID("peer-b"),
			peer.ID("peer-c"),
		},
	}
	dest := peer.ID("destination-peer")
	hopKeys := [][]byte{
		bytes.Repeat([]byte{0x11}, 32),
		bytes.Repeat([]byte{0x22}, 32),
		bytes.Repeat([]byte{0x33}, 32),
	}
	payload := bytes.Repeat([]byte("mixnet-onion-payload-"), 192)
	hopAEADs, err := prepareHopAEADs(hopKeys)
	if err != nil {
		b.Fatalf("prepareHopAEADs() error = %v", err)
	}

	b.Run("keys", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(payload)))
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			encrypted, err := encryptOnion(payload, c, dest, hopKeys)
			if err != nil {
				b.Fatalf("encryptOnion() error = %v", err)
			}
			if len(encrypted) == 0 {
				b.Fatal("expected encrypted onion bytes")
			}
		}
	})

	b.Run("prepared", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(payload)))
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			encrypted, err := encryptOnionWithAEADs(payload, c, dest, hopAEADs)
			if err != nil {
				b.Fatalf("encryptOnionWithAEADs() error = %v", err)
			}
			if len(encrypted) == 0 {
				b.Fatal("expected encrypted onion bytes")
			}
		}
	})
}
