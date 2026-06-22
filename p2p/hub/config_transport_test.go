package hub

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/protocol"
	mixnet "github.com/libp2p/go-libp2p/mixnet/core"
)

func TestNormalizeConfigDefaultsToHubTransport(t *testing.T) {
	cfg, err := normalizeConfig(Config{ProtocolID: protocol.ID("/hub/test/transport-default/1.0.0")})
	if err != nil {
		t.Fatalf("normalize config: %v", err)
	}
	if cfg.TransportMode != TransportModeHub {
		t.Fatalf("expected transport mode %q, got %q", TransportModeHub, cfg.TransportMode)
	}
	if cfg.Mixnet.Enabled {
		t.Fatal("expected mixnet to be disabled for hub transport")
	}
}

func TestNormalizeConfigMixnetModeInitializesMixnetConfig(t *testing.T) {
	cfg, err := normalizeConfig(Config{
		ProtocolID:    protocol.ID("/hub/test/transport-mixnet/1.0.0"),
		TransportMode: TransportModeMixnet,
	})
	if err != nil {
		t.Fatalf("normalize config: %v", err)
	}
	if cfg.TransportMode != TransportModeMixnet {
		t.Fatalf("expected transport mode %q, got %q", TransportModeMixnet, cfg.TransportMode)
	}
	if !cfg.Mixnet.Enabled {
		t.Fatal("expected mixnet to be enabled for mixnet transport")
	}
	if cfg.Mixnet.Config == nil {
		t.Fatal("expected non-nil mixnet config")
	}
}

func TestNormalizeConfigRejectsInvalidTransportMode(t *testing.T) {
	_, err := normalizeConfig(Config{
		ProtocolID:    protocol.ID("/hub/test/transport-invalid/1.0.0"),
		TransportMode: TransportMode("invalid"),
	})
	if err == nil {
		t.Fatal("expected invalid transport mode error")
	}
}

func TestNormalizeConfigRejectsInvalidMixnetConfig(t *testing.T) {
	badMix := mixnet.DefaultConfig()
	badMix.HopCount = 99
	_, err := normalizeConfig(Config{
		ProtocolID:    protocol.ID("/hub/test/transport-mixnet-invalid/1.0.0"),
		TransportMode: TransportModeMixnet,
		Mixnet: MixnetOptions{
			Config: badMix,
		},
	})
	if err == nil {
		t.Fatal("expected invalid mixnet config error")
	}
}
