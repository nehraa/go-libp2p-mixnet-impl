package upload

import (
	"testing"

	mixnet "github.com/libp2p/go-libp2p/mixnet/core"
	"github.com/libp2p/go-libp2p/p2p/hub"
)

func TestNormalizeConfigRejectsRandomnessFactorAboveOne(t *testing.T) {
	_, err := normalizeConfig(Config{
		RandomnessFactor: 1.01,
	})
	if err == nil {
		t.Fatal("expected randomness factor validation error")
	}
}

func TestNormalizeConfigRejectsMaxShardBytesAboveFrameLimit(t *testing.T) {
	_, err := normalizeConfig(Config{
		MaxFrameSize:  1024,
		MaxShardBytes: 2048,
	})
	if err == nil {
		t.Fatal("expected max shard bytes validation error")
	}
}

func TestNormalizeConfigSetsShardLimitDefaults(t *testing.T) {
	cfg, err := normalizeConfig(Config{})
	if err != nil {
		t.Fatalf("normalize config: %v", err)
	}
	if cfg.MaxShardBytes != cfg.MaxFrameSize {
		t.Fatalf("expected max shard bytes to default to max frame size (%d), got %d", cfg.MaxFrameSize, cfg.MaxShardBytes)
	}
	if cfg.MaxShardCount <= 0 {
		t.Fatalf("expected positive default max shard count, got %d", cfg.MaxShardCount)
	}
}

func TestNormalizeConfigRejectsNegativeValues(t *testing.T) {
	cases := []Config{
		{RandomnessFactor: -0.1},
		{MaxShardBytes: -1},
		{MaxShardCount: -1},
		{MaxConcurrency: -1},
	}
	for i, cfg := range cases {
		if _, err := normalizeConfig(cfg); err == nil {
			t.Fatalf("case %d: expected validation error", i)
		}
	}
}

func TestNormalizeConfigRejectsUnsupportedSuccessMode(t *testing.T) {
	_, err := normalizeConfig(Config{
		DefaultSuccessMode: SuccessMode("unsupported"),
	})
	if err == nil {
		t.Fatal("expected unsupported success mode error")
	}
}

func TestNormalizeHubConfigRejectsInvalidValues(t *testing.T) {
	invalids := []hub.Config{
		{},
		{ProtocolID: "/x", PingInterval: -1},
		{ProtocolID: "/x", PingTimeout: -1},
		{ProtocolID: "/x", EventBufferSize: -1},
		{ProtocolID: "/x", MetricsBufferSize: -1},
		{ProtocolID: "/x", ReadBufferSize: -1},
	}
	for i, cfg := range invalids {
		if _, err := normalizeHubConfig(cfg); err == nil {
			t.Fatalf("invalid hub config case %d expected error", i)
		}
	}

	normalized, err := normalizeHubConfig(hub.Config{ProtocolID: "/x"})
	if err != nil {
		t.Fatalf("expected valid hub config, got %v", err)
	}
	if normalized.ProtocolID != "/x" {
		t.Fatalf("expected protocol to be preserved, got %q", normalized.ProtocolID)
	}
}

func TestNormalizeHubConfigMixnetModeDefaultsConfig(t *testing.T) {
	normalized, err := normalizeHubConfig(hub.Config{
		ProtocolID:    "/x",
		TransportMode: hub.TransportModeMixnet,
	})
	if err != nil {
		t.Fatalf("normalize hub config: %v", err)
	}
	if normalized.TransportMode != hub.TransportModeMixnet {
		t.Fatalf("expected transport mode %q, got %q", hub.TransportModeMixnet, normalized.TransportMode)
	}
	if !normalized.Mixnet.Enabled {
		t.Fatal("expected mixnet to be enabled")
	}
	if normalized.Mixnet.Config == nil {
		t.Fatal("expected mixnet config to be initialized")
	}
}

func TestNormalizeHubConfigRejectsInvalidMixnetConfig(t *testing.T) {
	badMix := mixnet.DefaultConfig()
	badMix.HopCount = 0
	badMix.CircuitCount = 100
	_, err := normalizeHubConfig(hub.Config{
		ProtocolID:    "/x",
		TransportMode: hub.TransportModeMixnet,
		Mixnet: hub.MixnetOptions{
			Config: badMix,
		},
	})
	if err == nil {
		t.Fatal("expected invalid mixnet config error")
	}
}

func TestEffectiveSuccessModeOverrideAndInvalid(t *testing.T) {
	cfg := Config{DefaultSuccessMode: SuccessModeWriteAccepted}
	mode, err := cfg.effectiveSuccessMode("")
	if err != nil || mode != SuccessModeWriteAccepted {
		t.Fatalf("expected default write accepted, got mode=%s err=%v", mode, err)
	}
	mode, err = cfg.effectiveSuccessMode(SuccessModeAckOnPersist)
	if err != nil || mode != SuccessModeAckOnPersist {
		t.Fatalf("expected override ack on persist, got mode=%s err=%v", mode, err)
	}
	if _, err := cfg.effectiveSuccessMode(SuccessMode("bad")); err == nil {
		t.Fatal("expected invalid success mode error")
	}
}
