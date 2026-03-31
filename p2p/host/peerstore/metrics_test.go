package peerstore

import (
	"math/rand"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/test"
)

func TestLatencyEWMAFallsBackToDefaultSmoothing(t *testing.T) {
	m := NewMetrics()
	id, err := test.RandPeerID()
	if err != nil {
		t.Fatal(err)
	}

	original := LatencyEWMASmoothing
	LatencyEWMASmoothing = 2
	t.Cleanup(func() { LatencyEWMASmoothing = original })

	m.RecordLatency(id, 100*time.Millisecond)
	m.RecordLatency(id, 200*time.Millisecond)

	got := m.LatencyEWMA(id)
	want := 110 * time.Millisecond // 100ms blended with the default smoothing factor of 0.1
	if diff := got - want; diff < -time.Millisecond || diff > time.Millisecond {
		t.Fatalf("expected EWMA near %s, got %s", want, got)
	}
}

func TestLatencyEWMARemovePeer(t *testing.T) {
	m := NewMetrics()
	id, err := test.RandPeerID()
	if err != nil {
		t.Fatal(err)
	}

	m.RecordLatency(id, 100*time.Millisecond)
	if m.LatencyEWMA(id) == 0 {
		t.Fatal("expected a recorded latency")
	}

	m.RemovePeer(id)
	if got := m.LatencyEWMA(id); got != 0 {
		t.Fatalf("expected latency to be cleared, got %s", got)
	}
}

func TestLatencyEWMA(t *testing.T) {
	m := NewMetrics()
	id, err := test.RandPeerID()
	if err != nil {
		t.Fatal(err)
	}

	const exp = 100
	const mu = exp
	const sig = 10
	next := func() time.Duration { return time.Duration(rand.Intn(20) - 10 + mu) }

	for range 10 {
		m.RecordLatency(id, next())
	}

	lat := m.LatencyEWMA(id)
	diff := exp - lat
	if diff < 0 {
		diff = -diff
	}
	if diff > sig {
		t.Fatalf("latency outside of expected range. expected %d ± %d, got %d", exp, sig, lat)
	}
}
