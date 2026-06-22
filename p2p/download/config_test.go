package download

import (
	"testing"

	mixnet "github.com/libp2p/go-libp2p/mixnet/core"
	"github.com/libp2p/go-libp2p/p2p/hub"
)

func TestNormalizeConfigRejectsChunkTooLargeForFrame(t *testing.T) {
	_, err := normalizeConfig(Config{
		ChunkSize:    4096,
		MaxFrameSize: 1024,
	})
	if err == nil {
		t.Fatal("expected chunk/frame validation error")
	}
}

func TestNormalizeConfigDefaultsHolderRoot(t *testing.T) {
	cfg, err := normalizeConfig(Config{})
	if err != nil {
		t.Fatalf("normalize config: %v", err)
	}
	if cfg.HolderRoot == "" {
		t.Fatal("expected holder root default to be set")
	}
	if cfg.DownloadRoot == "" {
		t.Fatal("expected download root default to be set")
	}
}

func TestNormalizeHubConfigRejectsInvalidValues(t *testing.T) {
	tests := []hub.Config{
		{},
		{ProtocolID: defaultProtocolID, PingInterval: -1},
		{ProtocolID: defaultProtocolID, PingTimeout: -1},
		{ProtocolID: defaultProtocolID, EventBufferSize: -1},
	}
	for i, cfg := range tests {
		if _, err := normalizeHubConfig(cfg); err == nil {
			t.Fatalf("expected invalid hub config %d to fail", i)
		}
	}
}

func TestNormalizeHubConfigMixnetModeDefaultsConfig(t *testing.T) {
	cfg, err := normalizeHubConfig(hub.Config{
		ProtocolID:    defaultProtocolID,
		TransportMode: hub.TransportModeMixnet,
	})
	if err != nil {
		t.Fatalf("normalize hub config: %v", err)
	}
	if cfg.TransportMode != hub.TransportModeMixnet {
		t.Fatalf("expected transport mode %q, got %q", hub.TransportModeMixnet, cfg.TransportMode)
	}
	if !cfg.Mixnet.Enabled {
		t.Fatal("expected mixnet enabled")
	}
	if cfg.Mixnet.Config == nil {
		t.Fatal("expected non-nil mixnet config")
	}
}

func TestNormalizeHubConfigRejectsInvalidMixnetConfig(t *testing.T) {
	badMix := mixnet.DefaultConfig()
	badMix.CircuitCount = 100
	_, err := normalizeHubConfig(hub.Config{
		ProtocolID:    defaultProtocolID,
		TransportMode: hub.TransportModeMixnet,
		Mixnet: hub.MixnetOptions{
			Config: badMix,
		},
	})
	if err == nil {
		t.Fatal("expected invalid mixnet config error")
	}
}

func TestEffectiveModeRejectsUnsupportedMode(t *testing.T) {
	if _, err := effectiveMode("unsupported"); err == nil {
		t.Fatal("expected unsupported mode error")
	}
}
