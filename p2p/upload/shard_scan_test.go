package upload

import (
	"testing"
)

func TestScanShardsZeroCopyViews(t *testing.T) {
	input := []byte("one|two|three")
	shards, err := scanShards(input, []byte("|"), 3, false)
	if err != nil {
		t.Fatalf("scan shards: %v", err)
	}
	if len(shards) != 3 {
		t.Fatalf("expected 3 shards, got %d", len(shards))
	}
	if string(shards[0].Data) != "one" || string(shards[1].Data) != "two" || string(shards[2].Data) != "three" {
		t.Fatalf("unexpected shard data: %#v", shards)
	}

	input[0] = 'O'
	if string(shards[0].Data) != "One" {
		t.Fatal("expected shard data to reflect source buffer mutation")
	}
}

func TestScanShardsRejectsEmptyShardByDefault(t *testing.T) {
	_, err := scanShards([]byte("one||three"), []byte("|"), 0, false)
	if err == nil {
		t.Fatal("expected empty shard error")
	}
}
