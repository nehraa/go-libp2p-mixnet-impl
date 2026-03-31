package mixnet

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"runtime"
	"testing"
)

func TestEncryptSessionShardsWithKeyRoundTrip(t *testing.T) {
	session, err := newSessionKey(sessionCryptoModePerShardStream)
	if err != nil {
		t.Fatalf("newSessionKey() error = %v", err)
	}

	plaintext := bytes.Repeat([]byte("mixnet-session-shard-"), 64)
	shards, err := encryptSessionShardsWithKey(plaintext, session, 8, "stream-7")
	if err != nil {
		t.Fatalf("encryptSessionShardsWithKey() error = %v", err)
	}
	if len(shards) != 8 {
		t.Fatalf("len(shards) = %d, want 8", len(shards))
	}

	var reconstructed []byte
	for _, shard := range shards {
		decrypted, err := decryptSessionShardPayloadWithKey(shard.Data, session, shard.Index, "stream-7")
		if err != nil {
			t.Fatalf("decryptSessionShardPayloadWithKey() error = %v", err)
		}
		reconstructed = append(reconstructed, decrypted...)
	}

	if !bytes.Equal(reconstructed, plaintext) {
		t.Fatal("session shard round trip mismatch")
	}
}

func TestSessionNonceDerivationStability(t *testing.T) {
	base := bytes.Repeat([]byte{0x5a}, sessionNonceSize)

	var shardNonce [sessionNonceSize]byte
	fillSessionShardNonce(&shardNonce, base, 7)
	if !bytes.Equal(shardNonce[:], legacySessionShardNonce(base, 7)) {
		t.Fatal("per-shard nonce derivation changed")
	}

	var streamPayloadNonce [sessionNonceSize]byte
	fillSessionStreamNonce(&streamPayloadNonce, base, 42, -1)
	if !bytes.Equal(streamPayloadNonce[:], legacySessionStreamNonce(base, 42, -1)) {
		t.Fatal("stream payload nonce derivation changed")
	}

	var streamShardNonce [sessionNonceSize]byte
	fillSessionStreamNonce(&streamShardNonce, base, 42, 3)
	if !bytes.Equal(streamShardNonce[:], legacySessionStreamNonce(base, 42, 3)) {
		t.Fatal("stream shard nonce derivation changed")
	}
}

func TestShardCryptoWorkerCount(t *testing.T) {
	if got := shardCryptoWorkerCount(1, 1<<20); got != 1 {
		t.Fatalf("single shard should stay sequential, got %d workers", got)
	}
	if got := shardCryptoWorkerCount(8, 8<<10); got != 1 {
		t.Fatalf("small payload should stay sequential, got %d workers", got)
	}

	want := runtime.GOMAXPROCS(0)
	if want < 1 {
		want = 1
	}
	if want > 16 {
		want = 16
	}
	if got := shardCryptoWorkerCount(16, 128<<10); got != want {
		t.Fatalf("large workload worker count = %d, want %d", got, want)
	}
}

func legacySessionShardNonce(base []byte, shardIndex int) []byte {
	nonce := append([]byte(nil), base...)
	tail := binary.LittleEndian.Uint64(nonce[len(nonce)-8:])
	binary.LittleEndian.PutUint64(nonce[len(nonce)-8:], tail^uint64(shardIndex+1))
	return nonce
}

func legacySessionStreamNonce(base []byte, seq uint64, shardIndex int) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte(sessionStreamNonceDomain))
	_, _ = h.Write(base)
	var buf [12]byte
	binary.LittleEndian.PutUint64(buf[:8], seq)
	if shardIndex >= 0 {
		binary.LittleEndian.PutUint32(buf[8:], uint32(shardIndex+1))
	}
	_, _ = h.Write(buf[:])
	sum := h.Sum(nil)
	nonce := make([]byte, sessionNonceSize)
	copy(nonce, sum[:sessionNonceSize])
	return nonce
}
