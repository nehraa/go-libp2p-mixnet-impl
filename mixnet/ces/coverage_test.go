package ces

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"testing"
)

func TestNewCompressorWithLevelAndInvalidCompressor(t *testing.T) {
	t.Parallel()

	compressor := NewCompressorWithLevel("gzip", gzip.BestSpeed)
	gzipImpl, ok := compressor.(*gzipCompressor)
	if !ok {
		t.Fatalf("NewCompressorWithLevel(gzip) type = %T, want *gzipCompressor", compressor)
	}
	if gzipImpl.level != gzip.BestSpeed {
		t.Fatalf("gzip level = %d, want %d", gzipImpl.level, gzip.BestSpeed)
	}

	compressor = NewCompressorWithLevel("gzip", gzip.BestCompression+1)
	gzipImpl, ok = compressor.(*gzipCompressor)
	if !ok {
		t.Fatalf("NewCompressorWithLevel(gzip) type = %T, want *gzipCompressor", compressor)
	}
	if gzipImpl.level != gzip.DefaultCompression {
		t.Fatalf("invalid gzip level should fall back to default, got %d", gzipImpl.level)
	}

	if _, ok := NewCompressor("snappy").(*snappyCompressor); !ok {
		t.Fatal("NewCompressor(snappy) did not return *snappyCompressor")
	}

	invalid := NewCompressor("not-real")
	if _, ok := invalid.(invalidCompressor); !ok {
		t.Fatalf("NewCompressor(invalid) type = %T, want invalidCompressor", invalid)
	}

	if _, err := invalid.Compress([]byte("payload")); err == nil {
		t.Fatal("invalid compressor Compress() expected error")
	}
	if _, err := invalid.Decompress([]byte("payload")); err == nil {
		t.Fatal("invalid compressor Decompress() expected error")
	}
}

func TestCompressorEdgeCases(t *testing.T) {
	t.Parallel()

	gzipCompressor := NewCompressor("gzip")
	if out, err := gzipCompressor.Compress(nil); err != nil || len(out) != 0 {
		t.Fatalf("gzip Compress(nil) = (%v, %v), want empty slice and nil error", out, err)
	}
	if out, err := gzipCompressor.Decompress(nil); err != nil || len(out) != 0 {
		t.Fatalf("gzip Decompress(nil) = (%v, %v), want empty slice and nil error", out, err)
	}
	if _, err := gzipCompressor.Decompress([]byte{AlgoSnappy}); err == nil {
		t.Fatal("gzip Decompress() expected header mismatch error")
	}

	snappyCompressor := NewCompressor("snappy")
	if out, err := snappyCompressor.Compress(nil); err != nil || len(out) != 0 {
		t.Fatalf("snappy Compress(nil) = (%v, %v), want empty slice and nil error", out, err)
	}
	if out, err := snappyCompressor.Decompress(nil); err != nil || len(out) != 0 {
		t.Fatalf("snappy Decompress(nil) = (%v, %v), want empty slice and nil error", out, err)
	}
	if _, err := snappyCompressor.Decompress([]byte{AlgoGzip}); err == nil {
		t.Fatal("snappy Decompress() expected header mismatch error")
	}
	if _, err := snappyCompressor.Decompress([]byte{AlgoSnappy, 0x01}); err == nil {
		t.Fatal("snappy Decompress() expected decode error for invalid payload")
	}
}

func TestLayeredEncrypterHelpers(t *testing.T) {
	t.Parallel()

	encrypter := NewLayeredEncrypter(2)
	key, err := deriveLayerKey(1, "peer-a")
	if err != nil {
		t.Fatalf("deriveLayerKey() error = %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("deriveLayerKey() len = %d, want 32", len(key))
	}

	if _, err := deriveKeyFromNoise([]byte("mixnet"), 0); err != nil {
		t.Fatalf("deriveKeyFromNoise() error = %v", err)
	}

	if got := encrypter.HopCount(); got != 2 {
		t.Fatalf("HopCount() = %d, want 2", got)
	}

	if got := layeredPayloadLen(4, 12); got != 19 {
		t.Fatalf("layeredPayloadLen() = %d, want 19", got)
	}

	payload := make([]byte, 32)
	written := fillLayerPayload(payload, "peer-a", []byte("payload"))
	if written != 16 {
		t.Fatalf("fillLayerPayload() wrote %d bytes, want 16", written)
	}
	if !equalBytesString(payload[3:9], "peer-a") {
		t.Fatalf("fillLayerPayload() destination mismatch: %q", payload[3:9])
	}
	if !bytes.Equal(payload[9:16], []byte("payload")) {
		t.Fatalf("fillLayerPayload() payload mismatch: %q", payload[9:16])
	}
}

func TestLayeredEncrypterKeyGenerationAndErase(t *testing.T) {
	encrypter := NewLayeredEncrypter(8)
	destinations := []string{
		"peer-a", "peer-b", "peer-c", "peer-d",
		"peer-e", "peer-f", "peer-g", "peer-h",
	}
	keys := make([]*EncryptionKey, len(destinations))

	if err := encrypter.generateLayerKeys(destinations, keys); err != nil {
		t.Fatalf("generateLayerKeys() error = %v", err)
	}

	for i, key := range keys {
		if key == nil {
			t.Fatalf("keys[%d] is nil", i)
		}
		if len(key.Key) != 32 {
			t.Fatalf("keys[%d].Key len = %d, want 32", i, len(key.Key))
		}
		if key.Destination != destinations[i] {
			t.Fatalf("keys[%d].Destination = %q, want %q", i, key.Destination, destinations[i])
		}
	}

	EraseKeys(keys)
	for i, key := range keys {
		if key == nil {
			continue
		}
		if !allZero(key.Key) {
			t.Fatalf("keys[%d].Key was not erased", i)
		}
	}

	SecureEraseBytes(keys[0].Key)
	if !allZero(keys[0].Key) {
		t.Fatal("SecureEraseBytes() did not zero key material")
	}

	encrypter.SecureErase()
}

func TestSharderAndPipelineValidation(t *testing.T) {
	t.Parallel()

	if buf, release := borrowShardDataScratch(0); buf != nil {
		t.Fatalf("borrowShardDataScratch(0) = %v, want nil", buf)
	} else {
		release()
	}

	emptyScratch, release := borrowShardDataScratch(4)
	if len(emptyScratch) != 4 {
		t.Fatalf("borrowShardDataScratch() len = %d, want 4", len(emptyScratch))
	}
	release()

	invalid := NewSharder(3, 3)
	if _, err := invalid.Shard([]byte("payload")); err == nil {
		t.Fatal("invalid sharder Shard() expected error")
	}
	if _, err := invalid.Reconstruct(nil); err == nil {
		t.Fatal("invalid sharder Reconstruct() expected error")
	}

	sharder := NewSharder(1, 1)
	shards, err := sharder.Shard([]byte("mixnet"))
	if err != nil {
		t.Fatalf("Shard() error = %v", err)
	}
	reconstructed, err := sharder.Reconstruct(shards)
	if err != nil {
		t.Fatalf("Reconstruct() error = %v", err)
	}
	if !bytes.Equal(reconstructed, []byte("mixnet")) {
		t.Fatalf("Reconstruct() = %q, want %q", reconstructed, "mixnet")
	}

	if _, err := sharder.Reconstruct([]*Shard{{Index: 0, Data: []byte{1, 2, 3, 4, 5, 6, 7}}}); err == nil {
		t.Fatal("Reconstruct() expected error for short shard prefix")
	}

	shortPayload := make([]byte, 12)
	shortPayload[0] = 20
	if _, err := sharder.Reconstruct([]*Shard{{Index: 0, Data: shortPayload}}); err == nil {
		t.Fatal("Reconstruct() expected error for short single-shard payload")
	}

	cfg := &Config{HopCount: 2, CircuitCount: 5, Compression: "gzip"}
	pipeline := NewPipeline(cfg)
	if pipeline.Config() != cfg {
		t.Fatal("Config() did not return original config")
	}
	if pipeline.Compressor() == nil || pipeline.Sharder() == nil || pipeline.Encrypter() == nil {
		t.Fatal("pipeline accessors returned nil")
	}
	if got := pipeline.Sharder().Threshold(); got != 3 {
		t.Fatalf("default threshold = %d, want 3", got)
	}
	if got := pipeline.Sharder().TotalShards(); got != 5 {
		t.Fatalf("total shards = %d, want 5", got)
	}
}

func TestCESPipelineProcessAndReconstructErrors(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		HopCount:         2,
		CircuitCount:     4,
		Compression:      "snappy",
		ErasureThreshold: 2,
	}
	pipeline := NewPipeline(cfg)

	if _, _, err := pipeline.ProcessWithKeys(nil, []string{"peer-a", "peer-b"}); err == nil {
		t.Fatal("ProcessWithKeys() expected empty data error")
	}
	if _, _, err := pipeline.ProcessWithKeys([]byte("payload"), []string{"peer-a"}); err == nil {
		t.Fatal("ProcessWithKeys() expected destination count error")
	}

	data := bytes.Repeat([]byte("mixnet"), 8)
	shards, keys, err := pipeline.ProcessWithKeys(data, []string{"peer-a", "peer-b"})
	if err != nil {
		t.Fatalf("ProcessWithKeys() error = %v", err)
	}
	if len(shards) == 0 || len(keys) != 2 {
		t.Fatalf("ProcessWithKeys() produced %d shards and %d keys", len(shards), len(keys))
	}
	if _, err := pipeline.Reconstruct(shards[:1], keys); err == nil {
		t.Fatal("Reconstruct() expected insufficient shard error")
	}
	if _, err := pipeline.Reconstruct(shards[:2], keys[:1]); err == nil {
		t.Fatal("Reconstruct() expected key count error")
	}

	reconstructed, err := pipeline.Reconstruct(shards[:2], keys)
	if err != nil {
		t.Fatalf("Reconstruct() error = %v", err)
	}
	if !bytes.Equal(reconstructed, data) {
		t.Fatalf("Reconstruct() = %q, want %q", reconstructed, data)
	}
}

func TestSecureEraseAndUtilityFunctions(t *testing.T) {
	t.Parallel()

	data := []byte("sensitive")
	SecureEraseBytes(data)
	if !allZero(data) {
		t.Fatal("SecureEraseBytes() did not zero input")
	}

	keys := []*EncryptionKey{{Key: []byte("alpha")}, nil, {Key: []byte("beta")}}
	EraseKeys(keys)
	if !allZero(keys[0].Key) || !allZero(keys[2].Key) {
		t.Fatal("EraseKeys() did not zero key material")
	}

	if !equalBytesString([]byte("peer-a"), "peer-a") {
		t.Fatal("equalBytesString() should match identical values")
	}
	if equalBytesString([]byte("peer-a"), "peer-b") {
		t.Fatal("equalBytesString() should reject mismatched values")
	}
}

func TestNewPipelineDefaultsAndEmptyProcess(t *testing.T) {
	t.Parallel()

	cfg := &Config{HopCount: 1, CircuitCount: 1, Compression: "gzip"}
	pipeline := NewPipeline(cfg)
	if got := pipeline.Sharder().Threshold(); got != 1 {
		t.Fatalf("default threshold = %d, want 1", got)
	}
	if _, err := pipeline.Process([]byte("payload"), []string{"peer-a"}); err != nil {
		t.Fatalf("Process() error = %v", err)
	}
}

func TestNewPipelineRejectsInvalidRoundTripPaths(t *testing.T) {
	t.Parallel()

	cfg := &Config{HopCount: 2, CircuitCount: 3, Compression: "gzip", ErasureThreshold: 2}
	pipeline := NewPipeline(cfg)

	if _, err := pipeline.Reconstruct(nil, nil); err == nil {
		t.Fatal("Reconstruct() expected shard count error")
	}

	if _, _, err := pipeline.ProcessWithKeys(bytes.Repeat([]byte("x"), 8), []string{"peer-a", "peer-b"}); err != nil {
		t.Fatalf("ProcessWithKeys() error = %v", err)
	}
}

func allZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

func TestBorrowShardDataScratchZeroSize(t *testing.T) {
	t.Parallel()

	buf, release := borrowShardDataScratch(0)
	if buf != nil {
		t.Fatalf("borrowShardDataScratch(0) buf = %v, want nil", buf)
	}
	release()
}

func TestGzipCompressorRoundTripWithLevelReuse(t *testing.T) {
	t.Parallel()

	compressor := NewCompressorWithLevel("gzip", gzip.BestCompression)
	input := bytes.Repeat([]byte("mixnet-gzip-extra-"), 32)

	compressed, err := compressor.Compress(input)
	if err != nil {
		t.Fatalf("Compress() error = %v", err)
	}
	decompressed, err := compressor.Decompress(compressed)
	if err != nil {
		t.Fatalf("Decompress() error = %v", err)
	}
	if !bytes.Equal(decompressed, input) {
		t.Fatal("gzip level round trip mismatch")
	}
}

func TestLayeredEncrypterRoundTripWithMultipleWorkers(t *testing.T) {
	t.Parallel()

	encrypter := NewLayeredEncrypter(64)
	plaintext := bytes.Repeat([]byte("mixnet-layered-wide-"), 16)
	destinations := make([]string, 64)
	for i := range destinations {
		destinations[i] = fmt.Sprintf("peer-%02d", i)
	}

	ciphertext, keys, err := encrypter.Encrypt(plaintext, destinations)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	decrypted, err := encrypter.Decrypt(ciphertext, keys)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("wide layered round trip mismatch")
	}
}

func TestLayeredEncrypterRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	encrypter := NewLayeredEncrypter(2)
	if _, err := encrypter.Decrypt([]byte{1, 2, 3}, []*EncryptionKey{{Key: bytes.Repeat([]byte{1}, 32)}}); err == nil {
		t.Fatal("Decrypt() expected short ciphertext error")
	}
	if _, _, err := encrypter.Encrypt([]byte("payload"), []string{"peer-a"}); err == nil {
		t.Fatal("Encrypt() expected destination count error")
	}
	if _, err := encrypter.Decrypt([]byte{0, 1, 2, 3, 4}, []*EncryptionKey{{Key: bytes.Repeat([]byte{1}, 32)}, {Key: bytes.Repeat([]byte{1}, 32)}}); err == nil {
		t.Fatal("Decrypt() expected authentication failure")
	}
}

func TestCompressionErrorPaths(t *testing.T) {
	t.Parallel()

	compressor := NewCompressor("gzip")
	if _, err := compressor.Decompress([]byte{AlgoGzip, 0x01}); err == nil {
		t.Fatal("gzip Decompress() expected invalid gzip payload error")
	}
	if _, err := compressor.Compress([]byte("payload")); err != nil {
		t.Fatalf("Compress() error = %v", err)
	}
}
