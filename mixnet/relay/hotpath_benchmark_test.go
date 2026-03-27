package relay

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func BenchmarkDecryptHopPayload(b *testing.B) {
	key := bytes.Repeat([]byte{0x55}, 32)
	plaintext := bytes.Repeat([]byte("mixnet-relay-hop-payload-"), 96)
	ciphertext, err := encryptHopPayloadForBenchmark(key, plaintext)
	if err != nil {
		b.Fatalf("encryptHopPayloadForBenchmark() setup error = %v", err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(plaintext)))
	for i := 0; i < b.N; i++ {
		buf := append([]byte(nil), ciphertext...)
		if _, err := decryptHopPayload(key, buf); err != nil {
			b.Fatalf("decryptHopPayload() error = %v", err)
		}
	}
}

func encryptHopPayloadForBenchmark(key []byte, payload []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, payload, nil), nil
}
