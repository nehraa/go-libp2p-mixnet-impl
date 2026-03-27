package ces

import (
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/klauspost/reedsolomon"
)

var shardDataPool = sync.Pool{
	New: func() any {
		return make([][]byte, 0, 32)
	},
}

func borrowShardDataScratch(size int) ([][]byte, func()) {
	if size <= 0 {
		return nil, func() {}
	}

	buf := shardDataPool.Get().([][]byte)
	if cap(buf) < size {
		return make([][]byte, size), func() {}
	}

	buf = buf[:size]
	for i := range buf {
		buf[i] = nil
	}

	return buf, func() {
		for i := range buf {
			buf[i] = nil
		}
		shardDataPool.Put(buf[:0])
	}
}

// Shard represents a single piece of data resulting from the sharding process.
type Shard struct {
	// Index is the unique position of this shard in the original set.
	Index int
	// Data is the raw encrypted payload of the shard.
	Data []byte
}

// Sharder implements Reed-Solomon erasure coding to provide data redundancy across multiple paths.
type Sharder struct {
	totalShards int
	threshold   int // = dataShards
	encoder     reedsolomon.Encoder
	initErr     error
}

// NewSharder creates a new Sharder instance.
// totalShards is the total number of shards produced (data + parity).
// threshold is the minimum number of shards required for reconstruction.
func NewSharder(totalShards, threshold int) *Sharder {
	if threshold < 1 || threshold > totalShards {
		return &Sharder{
			totalShards: totalShards,
			threshold:   threshold,
			initErr:     fmt.Errorf("invalid sharder params: totalShards=%d threshold=%d", totalShards, threshold),
		}
	}
	if totalShards == 1 && threshold == 1 {
		return &Sharder{
			totalShards: totalShards,
			threshold:   threshold,
		}
	}
	if threshold == totalShards {
		return &Sharder{
			totalShards: totalShards,
			threshold:   threshold,
			initErr:     fmt.Errorf("invalid sharder params: totalShards=%d threshold=%d", totalShards, threshold),
		}
	}
	parityShards := totalShards - threshold
	enc, err := reedsolomon.New(threshold, parityShards)
	if err != nil {
		return &Sharder{
			totalShards: totalShards,
			threshold:   threshold,
			initErr:     fmt.Errorf("failed to create reed-solomon encoder: %w", err),
		}
	}
	return &Sharder{
		totalShards: totalShards,
		threshold:   threshold,
		encoder:     enc,
	}
}

// Shard splits the data into totalShards pieces, including parity shards for redundancy.
func (s *Sharder) Shard(data []byte) ([]*Shard, error) {
	if s == nil {
		return nil, fmt.Errorf("sharder is nil")
	}
	if s.initErr != nil {
		return nil, s.initErr
	}
	dataShards := s.threshold
	if s.totalShards == 1 && s.threshold == 1 {
		payload := make([]byte, 8+len(data))
		binary.LittleEndian.PutUint64(payload[:8], uint64(len(data)))
		copy(payload[8:], data)
		return []*Shard{{Index: 0, Data: payload}}, nil
	}

	// Prepend 8-byte original data length so we can trim padding on reconstruction.
	origLen := uint64(len(data))
	payload := make([]byte, 8+len(data))
	binary.LittleEndian.PutUint64(payload[:8], origLen)
	copy(payload[8:], data)

	// Calculate per-shard size; pad payload to fill all data shards evenly.
	shardSize := (len(payload) + dataShards - 1) / dataShards
	if shardSize == 0 {
		shardSize = 1
	}
	paddedLen := shardSize * dataShards
	padded := make([]byte, paddedLen)
	copy(padded, payload)

	// Allocate data + parity shard slices.
	shards := make([][]byte, s.totalShards)
	for i := 0; i < dataShards; i++ {
		shards[i] = padded[i*shardSize : (i+1)*shardSize]
	}
	for i := dataShards; i < s.totalShards; i++ {
		shards[i] = make([]byte, shardSize)
	}

	if err := s.encoder.Encode(shards); err != nil {
		return nil, fmt.Errorf("failed to encode: %w", err)
	}

	result := make([]*Shard, s.totalShards)
	for i := 0; i < s.totalShards; i++ {
		cp := make([]byte, len(shards[i]))
		copy(cp, shards[i])
		result[i] = &Shard{Index: i, Data: cp}
	}
	return result, nil
}

// Reconstruct uses Reed-Solomon decoding to recover the original data from a partial set of shards.
func (s *Sharder) Reconstruct(shards []*Shard) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("sharder is nil")
	}
	if s.initErr != nil {
		return nil, s.initErr
	}
	if len(shards) < s.threshold {
		return nil, fmt.Errorf("insufficient shards: have %d, need %d", len(shards), s.threshold)
	}
	if s.totalShards == 1 && s.threshold == 1 {
		if len(shards) == 0 || shards[0] == nil {
			return nil, fmt.Errorf("missing single shard")
		}
		combined := shards[0].Data
		if len(combined) < 8 {
			return nil, fmt.Errorf("reconstructed data too short to contain length prefix")
		}
		origLen := binary.LittleEndian.Uint64(combined[:8])
		payload := combined[8:]
		if uint64(len(payload)) < origLen {
			return nil, fmt.Errorf("reconstructed payload shorter than expected: got %d, want %d", len(payload), origLen)
		}
		return payload[:origLen], nil
	}

	// Place provided shards into a full-length slice (nil = missing).
	shardData, releaseScratch := borrowShardDataScratch(s.totalShards)
	defer releaseScratch()
	for _, sh := range shards {
		if sh.Index >= 0 && sh.Index < s.totalShards {
			shardData[sh.Index] = sh.Data
		}
	}

	if err := s.encoder.Reconstruct(shardData); err != nil {
		return nil, fmt.Errorf("failed to reconstruct: %w", err)
	}

	// Join only the data shards (first threshold shards).
	dataShards := s.threshold
	shardSize := len(shardData[0])
	combined := make([]byte, 0, dataShards*shardSize)
	for i := 0; i < dataShards; i++ {
		combined = append(combined, shardData[i]...)
	}

	// Extract original length from the 8-byte prefix.
	if len(combined) < 8 {
		return nil, fmt.Errorf("reconstructed data too short to contain length prefix")
	}
	origLen := binary.LittleEndian.Uint64(combined[:8])
	payload := combined[8:]
	if uint64(len(payload)) < origLen {
		return nil, fmt.Errorf("reconstructed payload shorter than expected: got %d, want %d", len(payload), origLen)
	}
	return payload[:origLen], nil
}

// Threshold returns the minimum number of shards required to reconstruct the original data.
func (s *Sharder) Threshold() int {
	return s.threshold
}

// TotalShards returns the total number of shards (data + parity) produced by the sharder.
func (s *Sharder) TotalShards() int {
	return s.totalShards
}
