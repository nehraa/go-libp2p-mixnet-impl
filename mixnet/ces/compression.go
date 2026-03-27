package ces

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"sync"

	"github.com/golang/snappy"
)

// Compression algorithm identifiers used in the Mixnet protocol header.
const (
	// AlgoGzip indicates that the payload is compressed using Gzip.
	AlgoGzip byte = 0x01
	// AlgoSnappy indicates that the payload is compressed using Snappy.
	AlgoSnappy byte = 0x02
)

// Compressor is an interface for algorithms that can compress and decompress data.
type Compressor interface {
	// Compress compresses the provided data and returns the result with an algorithm-specific header.
	Compress(data []byte) ([]byte, error)
	// Decompress removes the header and decompresses the provided data.
	Decompress(data []byte) ([]byte, error)
}

// gzipCompressor implements the Compressor interface using the Gzip algorithm.
type gzipCompressor struct {
	level      int
	writerPool sync.Pool
	readerPool sync.Pool
	bufferPool sync.Pool
}

type gzipReaderState struct {
	reader *gzip.Reader
}

// NewCompressor returns a new Compressor for the specified algorithm ("gzip" or "snappy").
func NewCompressor(algo string) Compressor {
	switch algo {
	case "gzip":
		return newGzipCompressor(gzip.DefaultCompression)
	case "snappy":
		return &snappyCompressor{}
	default:
		return invalidCompressor{algo: algo}
	}
}

// NewCompressorWithLevel returns a new Compressor for the specified algorithm and compression level.
func NewCompressorWithLevel(algo string, level int) Compressor {
	switch algo {
	case "gzip":
		if level < gzip.HuffmanOnly || level > gzip.BestCompression {
			level = gzip.DefaultCompression
		}
		return newGzipCompressor(level)
	case "snappy":
		return &snappyCompressor{}
	default:
		return invalidCompressor{algo: algo}
	}
}

func newGzipCompressor(level int) *gzipCompressor {
	c := &gzipCompressor{level: level}
	c.bufferPool.New = func() any {
		return new(bytes.Buffer)
	}
	c.readerPool.New = func() any {
		return &gzipReaderState{}
	}
	c.writerPool.New = func() any {
		gw, err := gzip.NewWriterLevel(io.Discard, level)
		if err != nil {
			panic(err)
		}
		return gw
	}
	return c
}

type invalidCompressor struct {
	algo string
}

func (c invalidCompressor) Compress([]byte) ([]byte, error) {
	return nil, fmt.Errorf("unsupported compression algorithm: %s", c.algo)
}

func (c invalidCompressor) Decompress([]byte) ([]byte, error) {
	return nil, fmt.Errorf("unsupported compression algorithm: %s", c.algo)
}

// Compress compresses data using Gzip and prepends the AlgoGzip header.
func (c *gzipCompressor) Compress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}

	buf := c.bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer c.bufferPool.Put(buf)
	buf.WriteByte(AlgoGzip)

	gw := c.writerPool.Get().(*gzip.Writer)
	gw.Reset(buf)
	defer c.writerPool.Put(gw)

	_, err := gw.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to compress: %w", err)
	}

	if err := gw.Close(); err != nil {
		return nil, fmt.Errorf("failed to close gzip writer: %w", err)
	}

	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())
	return out, nil
}

// Decompress validates the header and decompresses data using Gzip.
func (c *gzipCompressor) Decompress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}

	if data[0] != AlgoGzip {
		return nil, fmt.Errorf("unexpected algorithm ID: want %d, got %d", AlgoGzip, data[0])
	}

	state := c.readerPool.Get().(*gzipReaderState)
	defer c.readerPool.Put(state)

	reader := bytes.NewReader(data[1:])
	if state.reader == nil {
		gr, err := gzip.NewReader(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		state.reader = gr
	} else if err := state.reader.Reset(reader); err != nil {
		return nil, fmt.Errorf("failed to reset gzip reader: %w", err)
	}
	defer state.reader.Close()

	buf := c.bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer c.bufferPool.Put(buf)
	if _, err := buf.ReadFrom(state.reader); err != nil {
		return nil, fmt.Errorf("failed to decompress: %w", err)
	}

	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())
	return out, nil
}

// snappyCompressor implements the Compressor interface using the Snappy algorithm.
type snappyCompressor struct{}

// Compress compresses data using Snappy and prepends the AlgoSnappy header.
func (c *snappyCompressor) Compress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}
	out := make([]byte, 1+snappy.MaxEncodedLen(len(data)))
	out[0] = AlgoSnappy
	encoded := snappy.Encode(out[1:], data)
	return out[:1+len(encoded)], nil
}

// Decompress validates the header and decompresses data using Snappy.
func (c *snappyCompressor) Decompress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}

	if data[0] != AlgoSnappy {
		return nil, fmt.Errorf("unexpected algorithm ID: want %d, got %d", AlgoSnappy, data[0])
	}

	decodedLen, err := snappy.DecodedLen(data[1:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, decodedLen)
	return snappy.Decode(out, data[1:])
}

// ErrInvalidAlgorithm is returned when an unsupported compression algorithm is requested.
var ErrInvalidAlgorithm = fmt.Errorf("invalid compression algorithm")
