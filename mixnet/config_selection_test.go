package mixnet

import "testing"

func TestSetSelectionModeNormalizesAliases(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	if err := cfg.SetSelectionMode(SelectionMode("sc")); err != nil {
		t.Fatalf("SetSelectionMode(sc) error = %v", err)
	}
	if cfg.SelectionMode != SelectionModeSingleCircle {
		t.Fatalf("SelectionMode = %q, want %q", cfg.SelectionMode, SelectionModeSingleCircle)
	}
}

func TestValidateCanonicalizesExtendedSelectionModes(t *testing.T) {
	t.Parallel()

	cfg := &MixnetConfig{
		HopCount:       2,
		CircuitCount:   3,
		UseCESPipeline: false,
		SelectionMode:  SelectionMode("rm"),
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if cfg.SelectionMode != SelectionModeRegionalMixnet {
		t.Fatalf("SelectionMode = %q, want %q", cfg.SelectionMode, SelectionModeRegionalMixnet)
	}
}

func TestValidateRejectsUnknownSelectionMode(t *testing.T) {
	t.Parallel()

	cfg := &MixnetConfig{
		HopCount:       2,
		CircuitCount:   3,
		UseCESPipeline: false,
		SelectionMode:  SelectionMode("made-up"),
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() expected error for unknown selection mode")
	}
}
