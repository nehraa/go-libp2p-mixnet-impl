package upload

import (
	"bytes"
	"fmt"
)

func scanShards(buffer []byte, delimiter []byte, expectedShardCount int, allowEmpty bool) ([]ShardView, error) {
	if len(buffer) == 0 {
		return nil, fmt.Errorf("%w: buffer is empty", ErrInvalidRequest)
	}
	if len(delimiter) == 0 {
		return nil, fmt.Errorf("%w: delimiter is required", ErrInvalidRequest)
	}

	start := 0
	shards := make([]ShardView, 0, 8)
	for {
		offset := bytes.Index(buffer[start:], delimiter)
		if offset < 0 {
			end := len(buffer)
			if !allowEmpty && end == start {
				return nil, fmt.Errorf("%w: trailing empty shard is not allowed", ErrInvalidRequest)
			}
			shards = append(shards, ShardView{
				Index: len(shards),
				Start: start,
				End:   end,
				Data:  buffer[start:end],
			})
			break
		}

		end := start + offset
		if !allowEmpty && end == start {
			return nil, fmt.Errorf("%w: empty shard at index %d", ErrInvalidRequest, len(shards))
		}
		shards = append(shards, ShardView{
			Index: len(shards),
			Start: start,
			End:   end,
			Data:  buffer[start:end],
		})
		start = end + len(delimiter)
	}

	if expectedShardCount > 0 && len(shards) != expectedShardCount {
		return nil, fmt.Errorf(
			"%w: expected %d shards, got %d",
			ErrInvalidRequest,
			expectedShardCount,
			len(shards),
		)
	}
	return shards, nil
}
