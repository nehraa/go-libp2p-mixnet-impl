package shardxfer

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	encoded, err := EncodeFrame(0x11, []byte("abc"), 1024)
	if err != nil {
		t.Fatalf("encode frame: %v", err)
	}

	frames, remaining, err := DecodeBuffer(encoded, 1024)
	if err != nil {
		t.Fatalf("decode buffer: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("unexpected remaining bytes: %d", len(remaining))
	}
	if len(frames) != 1 {
		t.Fatalf("expected one frame, got %d", len(frames))
	}
	if frames[0].Kind != 0x11 {
		t.Fatalf("unexpected frame kind: %d", frames[0].Kind)
	}
	if string(frames[0].Payload) != "abc" {
		t.Fatalf("unexpected payload: %q", string(frames[0].Payload))
	}

	frame, err := ReadFrame(bytes.NewReader(encoded), 1024)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if frame.Kind != 0x11 || string(frame.Payload) != "abc" {
		t.Fatalf("unexpected read frame: kind=%d payload=%q", frame.Kind, string(frame.Payload))
	}
}

func TestDecodeBufferIncompleteFrame(t *testing.T) {
	encoded, err := EncodeFrame(0x22, []byte("hello"), 1024)
	if err != nil {
		t.Fatalf("encode frame: %v", err)
	}
	partial := encoded[:len(encoded)-2]
	frames, remaining, err := DecodeBuffer(partial, 1024)
	if err != nil {
		t.Fatalf("decode partial frame: %v", err)
	}
	if len(frames) != 0 {
		t.Fatalf("expected 0 frames, got %d", len(frames))
	}
	if len(remaining) != len(partial) {
		t.Fatalf("expected %d remaining bytes, got %d", len(partial), len(remaining))
	}
}

func TestDecodeBufferRejectsOversize(t *testing.T) {
	encoded, err := EncodeFrame(0x23, []byte("hello"), 1024)
	if err != nil {
		t.Fatalf("encode frame: %v", err)
	}
	_, _, err = DecodeBuffer(encoded, 3)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("expected ErrFrameTooLarge, got %v", err)
	}
}
