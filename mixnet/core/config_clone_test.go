package mixnet

import "testing"

func TestMixnetConfigCloneCopiesState(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PayloadPaddingStrategy = PaddingStrategyBuckets
	cfg.PayloadPaddingBuckets = []int{64, 128, 256}
	cfg.EnableSessionRouting = true
	cfg.Lock()

	clone := cfg.Clone()
	if clone == cfg {
		t.Fatal("Clone returned the original pointer")
	}
	if !clone.IsLocked() {
		t.Fatal("Clone should preserve locked state")
	}
	if clone.HopCount != cfg.HopCount || clone.CircuitCount != cfg.CircuitCount {
		t.Fatalf("Clone copied unexpected scalar values: got hops=%d circuits=%d", clone.HopCount, clone.CircuitCount)
	}
	if len(clone.PayloadPaddingBuckets) != len(cfg.PayloadPaddingBuckets) {
		t.Fatalf("Clone copied unexpected bucket count: got %d want %d", len(clone.PayloadPaddingBuckets), len(cfg.PayloadPaddingBuckets))
	}

	clone.PayloadPaddingBuckets[0] = 999
	if cfg.PayloadPaddingBuckets[0] == 999 {
		t.Fatal("Clone shares PayloadPaddingBuckets backing storage with the source")
	}
}
