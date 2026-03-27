package circuit

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestAdaptiveTargetCircuitCountScalesUpWhenRelayHeadroomExists(t *testing.T) {
	t.Parallel()

	mgr := NewCircuitManager(&CircuitConfig{
		HopCount:               2,
		CircuitCount:           2,
		StreamTimeout:          time.Second,
		AdaptiveScalingEnabled: true,
		AdaptiveScalingMin:     1,
		AdaptiveScalingMax:     3,
		AdaptiveScalingStep:    1,
	})

	relays := testAdaptiveRelayInfos(6)
	if got := mgr.AdaptiveTargetCircuitCount(len(relays)); got != 3 {
		t.Fatalf("AdaptiveTargetCircuitCount() = %d, want 3", got)
	}

	circuits, err := mgr.BuildCircuits(context.Background(), peer.ID("dest"), relays)
	if err != nil {
		t.Fatalf("BuildCircuits() error = %v", err)
	}
	if len(circuits) != 3 {
		t.Fatalf("BuildCircuits() len = %d, want 3", len(circuits))
	}
}

func TestAdaptiveTargetCircuitCountScalesDownUnderRelayPressure(t *testing.T) {
	t.Parallel()

	mgr := NewCircuitManager(&CircuitConfig{
		HopCount:               2,
		CircuitCount:           3,
		StreamTimeout:          time.Second,
		AdaptiveScalingEnabled: true,
		AdaptiveScalingMin:     2,
		AdaptiveScalingMax:     4,
		AdaptiveScalingStep:    1,
	})

	relays := testAdaptiveRelayInfos(4)
	if got := mgr.AdaptiveTargetCircuitCount(len(relays)); got != 2 {
		t.Fatalf("AdaptiveTargetCircuitCount() = %d, want 2", got)
	}

	circuits, err := mgr.BuildCircuits(context.Background(), peer.ID("dest"), relays)
	if err != nil {
		t.Fatalf("BuildCircuits() error = %v", err)
	}
	if len(circuits) != 2 {
		t.Fatalf("BuildCircuits() len = %d, want 2", len(circuits))
	}
}

func TestAdaptiveTargetCircuitCountDefaultsToFixedMode(t *testing.T) {
	t.Parallel()

	mgr := NewCircuitManager(&CircuitConfig{
		HopCount:      2,
		CircuitCount:  2,
		StreamTimeout: time.Second,
	})

	if got := mgr.AdaptiveTargetCircuitCount(6); got != 2 {
		t.Fatalf("AdaptiveTargetCircuitCount() = %d, want 2", got)
	}
}

func testAdaptiveRelayInfos(count int) []RelayInfo {
	relays := make([]RelayInfo, 0, count)
	for i := 0; i < count; i++ {
		id := peer.ID(fmt.Sprintf("relay-%d", i))
		relays = append(relays, RelayInfo{
			PeerID:    id,
			AddrInfo:  peer.AddrInfo{ID: id},
			Latency:   time.Duration(i+1) * time.Millisecond,
			Connected: true,
		})
	}
	return relays
}
