package mixnet

import (
	"testing"
	"time"
)

func TestUnregisterSessionPreservesCompletionTombstone(t *testing.T) {
	sessionID := "completed-session"
	h := &DestinationHandler{
		sessions:       map[string]*sessionMailbox{sessionID: {ch: make(chan []byte, 1)}},
		sessionDone:    map[string]time.Time{sessionID: time.Now().Add(time.Minute)},
		inboundCh:      make(chan string, 1),
		sessionPending: make(map[string]map[uint64][]byte),
		sessionNextSeq: make(map[string]uint64),
		timeout:        25 * time.Millisecond,
	}

	h.unregisterSession(sessionID)

	h.mu.Lock()
	completed := h.sessionCompletedLocked(sessionID)
	h.mu.Unlock()
	if !completed {
		t.Fatal("expected completed session tombstone to survive unregister")
	}

	h.ensureSession(sessionID)

	select {
	case reopened := <-h.inboundCh:
		t.Fatalf("completed session reopened after unregister: %s", reopened)
	default:
	}

	time.Sleep(40 * time.Millisecond)
	h.ensureSession(sessionID)
	select {
	case reopened := <-h.inboundCh:
		if reopened != sessionID {
			t.Fatalf("reopened session ID = %s, want %s", reopened, sessionID)
		}
	default:
		t.Fatal("expected tombstone to expire and allow session reuse")
	}
}
