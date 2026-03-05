package mixnet

import (
	"io"
	"testing"
)

func TestMixnetStream_OpenStream(t *testing.T) {
	if DefaultConfig() == nil {
		t.Fatal("expected default config")
	}
}

// TestMixnetStream_ReadWriteClose exercises the Read, Write, and Close methods of
// MixStream without requiring a real libp2p host or network connection.
func TestMixnetStream_ReadWriteClose(t *testing.T) {
	sessionID := "test-session"
	ch := make(chan []byte, 2)
	destHandler := &DestinationHandler{
		sessions: map[string]chan []byte{sessionID: ch},
	}

	// Use an inbound-only stream (dest="") so Write short-circuits without
	// calling SendWithSession, avoiding the need for a real Mixnet instance.
	stream := &MixStream{
		mixnet:    &Mixnet{destHandler: destHandler},
		dest:      "",
		sessionID: sessionID,
		ch:        ch,
	}

	// Exercise Write on inbound-only stream: expect error without panic.
	_, err := stream.Write([]byte("hello"))
	if err == nil {
		t.Fatal("expected Write on inbound-only stream to return error")
	}

	// Exercise Read: queue data on the channel and verify it is returned.
	ch <- []byte("hello")
	buf := make([]byte, 16)
	n, err := stream.Read(buf)
	if err != nil {
		t.Fatalf("Read returned unexpected error: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("Read returned unexpected data: %q", buf[:n])
	}

	// Exercise Close.
	if err := stream.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	// Read after Close should return EOF.
	_, err = stream.Read(buf)
	if err != io.EOF {
		t.Fatalf("expected io.EOF after Close, got %v", err)
	}

	// Write after Close should return ErrClosedPipe.
	_, err = stream.Write([]byte("after close"))
	if err != io.ErrClosedPipe {
		t.Fatalf("expected io.ErrClosedPipe after Close, got %v", err)
	}

	// Calling Close again should be idempotent.
	if err := stream.Close(); err != nil {
		t.Fatalf("second Close returned error: %v", err)
	}
}

