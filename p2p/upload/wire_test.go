package upload

import (
	"bytes"
	"strings"
	"testing"
)

func TestWireDataFrameRoundTrip(t *testing.T) {
	frame, err := encodeDataFrame(dataFrame{
		UploadID:   "upload-1",
		ShardIndex: 2,
		ShardCount: 5,
		Payload:    []byte("payload"),
	})
	if err != nil {
		t.Fatalf("encode data frame: %v", err)
	}
	if len(frame) < 5 {
		t.Fatal("frame too short")
	}

	frames, remaining, err := decodePayloadFrames(frame, 1024)
	if err != nil {
		t.Fatalf("decode payload frames: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("expected no remaining bytes, got %d", len(remaining))
	}
	if len(frames) != 1 {
		t.Fatalf("expected one frame payload, got %d", len(frames))
	}
	got, err := decodeDataFrame(frames[0])
	if err != nil {
		t.Fatalf("decode data frame: %v", err)
	}
	if got.UploadID != "upload-1" || got.ShardIndex != 2 || got.ShardCount != 5 || string(got.Payload) != "payload" {
		t.Fatalf("unexpected frame: %+v", got)
	}
}

func TestWireAckFrameRoundTrip(t *testing.T) {
	frame, err := encodeAckFrame(ackFrame{
		UploadID:   "upload-2",
		ShardIndex: 1,
		Accepted:   true,
		Message:    "ok",
	})
	if err != nil {
		t.Fatalf("encode ack frame: %v", err)
	}
	frames, remaining, err := decodePayloadFrames(frame, 1024)
	if err != nil {
		t.Fatalf("decode payload frames: %v", err)
	}
	if len(remaining) != 0 || len(frames) != 1 {
		t.Fatalf("unexpected decode result frames=%d remaining=%d", len(frames), len(remaining))
	}
	got, err := decodeAckFrame(frames[0])
	if err != nil {
		t.Fatalf("decode ack frame: %v", err)
	}
	if got.UploadID != "upload-2" || got.ShardIndex != 1 || !got.Accepted || got.Message != "ok" {
		t.Fatalf("unexpected ack frame: %+v", got)
	}
}

func TestWireDecodeAndEncodeRejectMalformedFrames(t *testing.T) {
	if _, err := encodeDataFramePrefix("", 0, 1, 0, 1024); err == nil {
		t.Fatal("expected empty upload id error")
	}
	if _, err := encodeDataFramePrefix("upload-1", -1, 1, 0, 1024); err == nil {
		t.Fatal("expected invalid shard metadata error")
	}
	if _, err := encodeDataFramePrefix("upload-1", 0, 1, 2048, 32); err == nil {
		t.Fatal("expected frame too large error")
	}
	if _, err := encodeAckFrame(ackFrame{UploadID: "upload-1", ShardIndex: -1}); err == nil {
		t.Fatal("expected invalid ack metadata error")
	}
	if _, err := encodeAckFrame(ackFrame{UploadID: "upload-1", ShardIndex: 0, Message: strings.Repeat("x", maxAckTextLen+1)}); err == nil {
		t.Fatal("expected long ack message error")
	}
	if _, err := decodeDataFrame([]byte{
		frameTypeAck, 0, 1, 'a',
		0, 0, 0, 1,
		0, 0, 0, 1,
		0, 0, 0, 0,
	}); err == nil {
		t.Fatal("expected invalid data frame type error")
	}
	if _, err := decodeAckFrame([]byte{
		frameTypeData, 0, 1, 'a',
		0, 0, 0, 1,
		1, 0, 0,
	}); err == nil {
		t.Fatal("expected invalid ack frame type error")
	}
	if _, err := decodeDataFrame([]byte{frameTypeAck}); err == nil {
		t.Fatal("expected short data frame error")
	}
	if _, err := decodeAckFrame([]byte{frameTypeData}); err == nil {
		t.Fatal("expected short ack frame error")
	}
	if _, err := readWireFrame(bytes.NewReader([]byte{0, 0, 0, 0}), 1024); err == nil {
		t.Fatal("expected zero sized frame error")
	}
	if _, err := readWireFrame(bytes.NewReader([]byte{0, 0, 8, 0}), 1024); err == nil {
		t.Fatal("expected oversized frame error")
	}
}

func TestWireDecodePayloadFramesHandlesPartialAndEmptyBuffers(t *testing.T) {
	frames, remaining, err := decodePayloadFrames(nil, 1024)
	if err != nil || len(frames) != 0 || len(remaining) != 0 {
		t.Fatalf("unexpected empty buffer result frames=%d remaining=%d err=%v", len(frames), len(remaining), err)
	}
	frames, remaining, err = decodePayloadFrames([]byte{0, 0, 0, 5, 1, 2}, 1024)
	if err != nil {
		t.Fatalf("unexpected partial buffer error: %v", err)
	}
	if len(frames) != 0 || len(remaining) != 6 {
		t.Fatalf("expected partial buffer to remain untouched, frames=%d remaining=%d", len(frames), len(remaining))
	}
	if _, _, err := decodePayloadFrames([]byte{0, 0, 0, 5, 1, 2}, 4); err == nil {
		t.Fatal("expected oversize frame error")
	}
}
