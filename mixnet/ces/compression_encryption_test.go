package ces

import (
	"bytes"
	"runtime"
	"testing"
)

func TestGzipCompressorRoundTripWithPoolReuse(t *testing.T) {
	t.Parallel()

	compressor := NewCompressor("gzip")
	inputs := [][]byte{
		bytes.Repeat([]byte("mixnet-compress-alpha-"), 32),
		bytes.Repeat([]byte("mixnet-compress-beta-"), 48),
	}

	for _, input := range inputs {
		compressed, err := compressor.Compress(input)
		if err != nil {
			t.Fatalf("Compress() error = %v", err)
		}
		decompressed, err := compressor.Decompress(compressed)
		if err != nil {
			t.Fatalf("Decompress() error = %v", err)
		}
		if !bytes.Equal(decompressed, input) {
			t.Fatal("gzip round trip mismatch")
		}
	}
}

func TestSnappyCompressorRoundTrip(t *testing.T) {
	t.Parallel()

	compressor := NewCompressor("snappy")
	inputs := [][]byte{
		bytes.Repeat([]byte("mixnet-snappy-alpha-"), 32),
		bytes.Repeat([]byte("mixnet-snappy-beta-"), 48),
	}

	for _, input := range inputs {
		compressed, err := compressor.Compress(input)
		if err != nil {
			t.Fatalf("Compress() error = %v", err)
		}
		decompressed, err := compressor.Decompress(compressed)
		if err != nil {
			t.Fatalf("Decompress() error = %v", err)
		}
		if !bytes.Equal(decompressed, input) {
			t.Fatal("snappy round trip mismatch")
		}
	}
}

func TestLayeredEncrypterRoundTrip(t *testing.T) {
	t.Parallel()

	encrypter := NewLayeredEncrypter(4)
	plaintext := bytes.Repeat([]byte("mixnet-layered-payload-"), 24)
	destinations := []string{"peer-a", "peer-b", "peer-c", "peer-d"}

	ciphertext, keys, err := encrypter.Encrypt(plaintext, destinations)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if len(keys) != len(destinations) {
		t.Fatalf("len(keys) = %d, want %d", len(keys), len(destinations))
	}

	decrypted, err := encrypter.Decrypt(ciphertext, keys)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("layered encryption round trip mismatch")
	}
}

func BenchmarkGzipCompressorDecompress(b *testing.B) {
	compressor := NewCompressor("gzip")
	payload := bytes.Repeat([]byte("mixnet-gzip-reader-pool-"), 256)

	compressed, err := compressor.Compress(payload)
	if err != nil {
		b.Fatalf("Compress() error = %v", err)
	}

	verified, err := compressor.Decompress(compressed)
	if err != nil {
		b.Fatalf("Decompress() verification error = %v", err)
	}
	if !bytes.Equal(verified, payload) {
		b.Fatal("verification round trip mismatch")
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		out, err := compressor.Decompress(compressed)
		if err != nil {
			b.Fatalf("Decompress() error = %v", err)
		}
		if len(out) != len(payload) {
			b.Fatalf("len(out) = %d, want %d", len(out), len(payload))
		}
	}
}

func BenchmarkLayeredEncrypterEncrypt(b *testing.B) {
	encrypter := NewLayeredEncrypter(4)
	payload := bytes.Repeat([]byte("mixnet-layered-benchmark-payload-"), 64)
	destinations := []string{"peer-a", "peer-b", "peer-c", "peer-d"}

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		if _, _, err := encrypter.Encrypt(payload, destinations); err != nil {
			b.Fatalf("Encrypt() error = %v", err)
		}
	}
}

func BenchmarkLayeredEncrypterDecrypt(b *testing.B) {
	encrypter := NewLayeredEncrypter(4)
	payload := bytes.Repeat([]byte("mixnet-layered-benchmark-payload-"), 64)
	destinations := []string{"peer-a", "peer-b", "peer-c", "peer-d"}
	ciphertext, keys, err := encrypter.Encrypt(payload, destinations)
	if err != nil {
		b.Fatalf("Encrypt() setup error = %v", err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		if _, err := encrypter.Decrypt(ciphertext, keys); err != nil {
			b.Fatalf("Decrypt() error = %v", err)
		}
	}
}

func TestCryptoWorkerCount(t *testing.T) {
	if got := cryptoWorkerCount(1); got != 1 {
		t.Fatalf("single unit should stay sequential, got %d workers", got)
	}

	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		workers = 1
	}
	if got := cryptoWorkerCount(workers); got != 1 {
		t.Fatalf("small unit count should stay sequential, got %d workers", got)
	}

	want := workers
	if want > workers*2 {
		want = workers
	}
	if got := cryptoWorkerCount(workers * 2); got != want {
		t.Fatalf("large unit worker count = %d, want %d", got, want)
	}
}
