package download

import (
	"testing"
)

func TestPullRequestFrameRoundTrip(t *testing.T) {
	raw, err := encodePullRequestFrame(pullRequestFrame{
		UploadID:   "upload-1",
		RequestID:  "req-1",
		ShardIndex: 3,
	})
	if err != nil {
		t.Fatalf("encode pull request: %v", err)
	}
	got, err := decodePullRequestFrame(raw)
	if err != nil {
		t.Fatalf("decode pull request: %v", err)
	}
	if got.UploadID != "upload-1" || got.RequestID != "req-1" || got.ShardIndex != 3 {
		t.Fatalf("unexpected frame: %+v", got)
	}
}

func TestChunkFrameRoundTrip(t *testing.T) {
	raw, err := encodeShardChunkFrame(shardChunkFrame{
		UploadID:   "upload-2",
		RequestID:  "req-2",
		ShardIndex: 2,
		Offset:     16,
		Data:       []byte("payload"),
	})
	if err != nil {
		t.Fatalf("encode chunk frame: %v", err)
	}
	got, err := decodeShardChunkFrame(raw)
	if err != nil {
		t.Fatalf("decode chunk frame: %v", err)
	}
	if got.UploadID != "upload-2" || got.RequestID != "req-2" || got.ShardIndex != 2 || got.Offset != 16 || string(got.Data) != "payload" {
		t.Fatalf("unexpected frame: %+v", got)
	}
}

func TestEndAndErrorFrameRoundTrip(t *testing.T) {
	endRaw, err := encodeShardEndFrame(shardEndFrame{
		UploadID:   "upload-3",
		RequestID:  "req-3",
		ShardIndex: 1,
		TotalBytes: 99,
	})
	if err != nil {
		t.Fatalf("encode end frame: %v", err)
	}
	endFrame, err := decodeShardEndFrame(endRaw)
	if err != nil {
		t.Fatalf("decode end frame: %v", err)
	}
	if endFrame.TotalBytes != 99 || endFrame.ShardIndex != 1 {
		t.Fatalf("unexpected end frame: %+v", endFrame)
	}

	errRaw, err := encodeErrorFrame(errorFrame{
		UploadID:   "upload-3",
		RequestID:  "req-3",
		ShardIndex: 1,
		Message:    "boom",
	})
	if err != nil {
		t.Fatalf("encode error frame: %v", err)
	}
	errFrame, err := decodeErrorFrame(errRaw)
	if err != nil {
		t.Fatalf("decode error frame: %v", err)
	}
	if errFrame.Message != "boom" || errFrame.ShardIndex != 1 {
		t.Fatalf("unexpected error frame: %+v", errFrame)
	}
}

func TestDecodeChunkFrameRejectsTruncatedPayload(t *testing.T) {
	raw, err := encodeShardChunkFrame(shardChunkFrame{
		UploadID:   "upload-4",
		RequestID:  "req-4",
		ShardIndex: 0,
		Offset:     0,
		Data:       []byte("abcd"),
	})
	if err != nil {
		t.Fatalf("encode chunk frame: %v", err)
	}
	_, err = decodeShardChunkFrame(raw[:len(raw)-1])
	if err == nil {
		t.Fatal("expected decode error for truncated chunk payload")
	}
}
