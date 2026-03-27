package ces

import (
	"bytes"
	"testing"
)

func BenchmarkGzipCompress(b *testing.B) {
	compressor := NewCompressor("gzip")
	payload := bytes.Repeat([]byte("mixnet-gzip-benchmark-"), 512)

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		if _, err := compressor.Compress(payload); err != nil {
			b.Fatalf("Compress() error = %v", err)
		}
	}
}

func BenchmarkGzipDecompress(b *testing.B) {
	compressor := NewCompressor("gzip")
	payload := bytes.Repeat([]byte("mixnet-gzip-benchmark-"), 512)
	compressed, err := compressor.Compress(payload)
	if err != nil {
		b.Fatalf("Compress() setup error = %v", err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		if _, err := compressor.Decompress(compressed); err != nil {
			b.Fatalf("Decompress() error = %v", err)
		}
	}
}

func BenchmarkSnappyCompress(b *testing.B) {
	compressor := NewCompressor("snappy")
	payload := bytes.Repeat([]byte("mixnet-snappy-benchmark-"), 512)

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		if _, err := compressor.Compress(payload); err != nil {
			b.Fatalf("Compress() error = %v", err)
		}
	}
}

func BenchmarkSnappyDecompress(b *testing.B) {
	compressor := NewCompressor("snappy")
	payload := bytes.Repeat([]byte("mixnet-snappy-benchmark-"), 512)
	compressed, err := compressor.Compress(payload)
	if err != nil {
		b.Fatalf("Compress() setup error = %v", err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		if _, err := compressor.Decompress(compressed); err != nil {
			b.Fatalf("Decompress() error = %v", err)
		}
	}
}

func BenchmarkSharderReconstruct(b *testing.B) {
	sharder := NewSharder(6, 4)
	payload := bytes.Repeat([]byte("mixnet-reconstruct-benchmark-"), 512)
	shards, err := sharder.Shard(payload)
	if err != nil {
		b.Fatalf("Shard() setup error = %v", err)
	}
	subset := shards[:4]

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		if _, err := sharder.Reconstruct(subset); err != nil {
			b.Fatalf("Reconstruct() error = %v", err)
		}
	}
}

func BenchmarkSharderShard(b *testing.B) {
	sharder := NewSharder(6, 4)
	payload := bytes.Repeat([]byte("mixnet-reconstruct-benchmark-"), 512)

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for i := 0; i < b.N; i++ {
		if _, err := sharder.Shard(payload); err != nil {
			b.Fatalf("Shard() error = %v", err)
		}
	}
}
