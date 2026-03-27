package mixnet

import (
	"bytes"
	"testing"

	"github.com/libp2p/go-libp2p/mixnet/ces"
)

func BenchmarkEncodePrivacyShardVariablePadding(b *testing.B) {
	payload := bytes.Repeat([]byte("mixnet-privacy-payload-"), 128)
	header := PrivacyShardHeader{
		SessionID:   []byte("bench-session"),
		ShardIndex:  2,
		TotalShards: 5,
		HasKeys:     true,
		KeyData:     bytes.Repeat([]byte{0x11}, 57),
		AuthTag:     bytes.Repeat([]byte{0x22}, 16),
	}
	paddingCfg := &PrivacyPaddingConfig{Enabled: true, MinBytes: 16, MaxBytes: 32}

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		if _, err := EncodePrivacyShard(payload, header, paddingCfg); err != nil {
			b.Fatalf("EncodePrivacyShard() error = %v", err)
		}
	}
}

func BenchmarkEncryptHopPayload(b *testing.B) {
	payload, err := buildHopPayload(0, "peer-next-hop", bytes.Repeat([]byte("mixnet-hop-payload-"), 96))
	if err != nil {
		b.Fatalf("buildHopPayload() error = %v", err)
	}
	key := bytes.Repeat([]byte{0x33}, 32)

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		if _, err := encryptHopPayload(key, payload); err != nil {
			b.Fatalf("encryptHopPayload() error = %v", err)
		}
	}
}

func BenchmarkSessionDataFramePayload(b *testing.B) {
	shard := &ces.Shard{
		Index: 1,
		Data:  bytes.Repeat([]byte("mixnet-session-shard-"), 128),
	}
	authTag := bytes.Repeat([]byte{0x44}, 16)

	b.ReportAllocs()
	b.SetBytes(int64(len(shard.Data)))
	for i := 0; i < b.N; i++ {
		if _, err := encodeSessionDataFramePayload("bench-session", true, 42, shard, 4, authTag); err != nil {
			b.Fatalf("encodeSessionDataFramePayload() error = %v", err)
		}
	}
}

func BenchmarkEncryptSessionShardsWithKey(b *testing.B) {
	payload := bytes.Repeat([]byte("mixnet-session-payload-"), 128)
	session, err := newSessionKey(sessionCryptoModePerShardStream)
	if err != nil {
		b.Fatalf("newSessionKey() error = %v", err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		if _, err := encryptSessionShardsWithKey(payload, session, 8, "stream-bench"); err != nil {
			b.Fatalf("encryptSessionShardsWithKey() error = %v", err)
		}
	}
}

func BenchmarkDecryptSessionShardPayloadWithKey(b *testing.B) {
	payload := bytes.Repeat([]byte("mixnet-session-payload-"), 128)
	session, err := newSessionKey(sessionCryptoModePerShardStream)
	if err != nil {
		b.Fatalf("newSessionKey() error = %v", err)
	}
	shards, err := encryptSessionShardsWithKey(payload, session, 8, "stream-bench")
	if err != nil {
		b.Fatalf("encryptSessionShardsWithKey() error = %v", err)
	}
	target := shards[3]

	b.ReportAllocs()
	b.SetBytes(int64(len(target.Data)))
	for i := 0; i < b.N; i++ {
		if _, err := decryptSessionShardPayloadWithKey(target.Data, session, target.Index, "stream-bench"); err != nil {
			b.Fatalf("decryptSessionShardPayloadWithKey() error = %v", err)
		}
	}
}

func BenchmarkDecodeSessionSetupDeliveryPayload(b *testing.B) {
	payload, err := encodeSessionSetupDeliveryPayload("bench-session-setup", bytes.Repeat([]byte{0x77}, 48))
	if err != nil {
		b.Fatalf("encodeSessionSetupDeliveryPayload() setup error = %v", err)
	}

	b.Run("copy", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(payload)))
		for i := 0; i < b.N; i++ {
			baseID, keyData, err := decodeSessionSetupDeliveryPayload(payload)
			if err != nil {
				b.Fatalf("decodeSessionSetupDeliveryPayload() error = %v", err)
			}
			if baseID == "" || len(keyData) != 48 {
				b.Fatal("unexpected session setup delivery decode result")
			}
		}
	})

	b.Run("view", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(payload)))
		for i := 0; i < b.N; i++ {
			baseID, keyData, err := decodeSessionSetupDeliveryPayloadView(payload)
			if err != nil {
				b.Fatalf("decodeSessionSetupDeliveryPayloadView() error = %v", err)
			}
			if baseID == "" || len(keyData) != 48 {
				b.Fatal("unexpected session setup delivery decode result")
			}
		}
	})
}
