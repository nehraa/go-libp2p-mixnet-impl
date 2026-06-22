package upload

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/libp2p/go-libp2p/core/protocol"
	mixnet "github.com/libp2p/go-libp2p/mixnet/core"
	"github.com/libp2p/go-libp2p/p2p/hub"
)

const (
	defaultProtocolID       = protocol.ID("/libp2p/upload/1.0.0")
	defaultDiscoverySuffix  = "-provider-v1"
	defaultSelectionMode    = "rtt"
	defaultSamplingSize     = 64
	defaultRandomnessFactor = 0.30
	defaultMaxFrameSize     = 8 * 1024 * 1024
	defaultAckTimeout       = 15 * time.Second
	defaultSendTimeout      = 30 * time.Second
	defaultReceiveTimeout   = 30 * time.Second
	defaultManifestRoot     = "upload_manifests"
	defaultReceiverRoot     = "upload_data"
	defaultMaxShardCount    = 4096
)

// Config controls sender and receiver upload behavior.
type Config struct {
	ProtocolID         protocol.ID
	DiscoveryNamespace string

	SelectionMode    string
	SamplingSize     int
	RandomnessFactor float64

	MaxFrameSize   int
	AckTimeout     time.Duration
	SendTimeout    time.Duration
	ReceiveTimeout time.Duration
	MaxShardBytes  int
	MaxShardCount  int

	ManifestRoot string
	ReceiverRoot string

	DefaultSuccessMode SuccessMode

	AdvertiseReceiver bool
	AllowEmptyShards  bool
	OverwriteShards   bool

	MaxConcurrency int

	HubConfig hub.Config

	Resolver              PeerResolver
	SenderManifestStore   SenderManifestStore
	ReceiverManifestStore ReceiverManifestStore
	ShardStore            ShardStore
	ShardPolicy           ShardValidationPolicy
}

func normalizeConfig(cfg Config) (Config, error) {
	if cfg.ProtocolID == "" {
		cfg.ProtocolID = defaultProtocolID
	}
	if cfg.DiscoveryNamespace == "" {
		cfg.DiscoveryNamespace = string(cfg.ProtocolID) + defaultDiscoverySuffix
	}
	if cfg.SelectionMode == "" {
		cfg.SelectionMode = defaultSelectionMode
	}
	if cfg.SamplingSize <= 0 {
		cfg.SamplingSize = defaultSamplingSize
	}
	if cfg.RandomnessFactor < 0 {
		return Config{}, fmt.Errorf("%w: randomness factor cannot be negative", ErrInvalidConfig)
	}
	if cfg.RandomnessFactor > 1 {
		return Config{}, fmt.Errorf("%w: randomness factor cannot exceed 1", ErrInvalidConfig)
	}
	if cfg.RandomnessFactor == 0 {
		cfg.RandomnessFactor = defaultRandomnessFactor
	}
	if cfg.MaxFrameSize <= 0 {
		cfg.MaxFrameSize = defaultMaxFrameSize
	}
	if cfg.AckTimeout <= 0 {
		cfg.AckTimeout = defaultAckTimeout
	}
	if cfg.SendTimeout <= 0 {
		cfg.SendTimeout = defaultSendTimeout
	}
	if cfg.ReceiveTimeout <= 0 {
		cfg.ReceiveTimeout = defaultReceiveTimeout
	}
	if cfg.MaxShardBytes < 0 {
		return Config{}, fmt.Errorf("%w: max shard bytes cannot be negative", ErrInvalidConfig)
	}
	if cfg.MaxShardBytes == 0 {
		cfg.MaxShardBytes = cfg.MaxFrameSize
	}
	if cfg.MaxShardBytes > cfg.MaxFrameSize {
		return Config{}, fmt.Errorf("%w: max shard bytes cannot exceed max frame size", ErrInvalidConfig)
	}
	if cfg.MaxShardCount < 0 {
		return Config{}, fmt.Errorf("%w: max shard count cannot be negative", ErrInvalidConfig)
	}
	if cfg.MaxShardCount == 0 {
		cfg.MaxShardCount = defaultMaxShardCount
	}
	if cfg.ManifestRoot == "" {
		cfg.ManifestRoot = defaultManifestRoot
	}
	if cfg.ReceiverRoot == "" {
		cfg.ReceiverRoot = defaultReceiverRoot
	}
	cfg.ManifestRoot = filepath.Clean(cfg.ManifestRoot)
	cfg.ReceiverRoot = filepath.Clean(cfg.ReceiverRoot)
	if cfg.DefaultSuccessMode == "" {
		cfg.DefaultSuccessMode = SuccessModeAckOnPersist
	}
	switch cfg.DefaultSuccessMode {
	case SuccessModeAckOnPersist, SuccessModeWriteAccepted:
	default:
		return Config{}, fmt.Errorf("%w: unsupported success mode %q", ErrInvalidConfig, cfg.DefaultSuccessMode)
	}
	if cfg.MaxConcurrency < 0 {
		return Config{}, fmt.Errorf("%w: max concurrency cannot be negative", ErrInvalidConfig)
	}

	cfg.HubConfig.ProtocolID = cfg.ProtocolID
	hubCfg, err := normalizeHubConfig(cfg.HubConfig)
	if err != nil {
		return Config{}, err
	}
	cfg.HubConfig = hubCfg
	return cfg, nil
}

func normalizeHubConfig(cfg hub.Config) (hub.Config, error) {
	if cfg.ProtocolID == "" {
		return hub.Config{}, fmt.Errorf("%w: hub protocol id is required", ErrInvalidConfig)
	}
	if cfg.PingInterval < 0 {
		return hub.Config{}, fmt.Errorf("%w: hub ping interval must be positive", ErrInvalidConfig)
	}
	if cfg.PingTimeout < 0 {
		return hub.Config{}, fmt.Errorf("%w: hub ping timeout must be positive", ErrInvalidConfig)
	}
	if cfg.EventBufferSize < 0 || cfg.MetricsBufferSize < 0 || cfg.ReadBufferSize < 0 {
		return hub.Config{}, fmt.Errorf("%w: hub buffer sizes must be positive", ErrInvalidConfig)
	}
	if cfg.TransportMode == "" {
		cfg.TransportMode = hub.TransportModeHub
	}
	switch cfg.TransportMode {
	case hub.TransportModeHub:
		cfg.Mixnet.Enabled = false
	case hub.TransportModeMixnet:
		cfg.Mixnet.Enabled = true
		mixCfg := cfg.Mixnet.Config
		if mixCfg == nil {
			mixCfg = mixnet.DefaultConfig()
		} else {
			mixCfg = mixCfg.Clone()
			mixCfg.InitDefaults()
		}
		if err := mixCfg.Validate(); err != nil {
			return hub.Config{}, fmt.Errorf("%w: invalid mixnet config: %v", ErrInvalidConfig, err)
		}
		cfg.Mixnet.Config = mixCfg
	default:
		return hub.Config{}, fmt.Errorf("%w: unsupported hub transport mode %q", ErrInvalidConfig, cfg.TransportMode)
	}
	return cfg, nil
}

func (cfg Config) effectiveSuccessMode(override SuccessMode) (SuccessMode, error) {
	mode := cfg.DefaultSuccessMode
	if override != "" {
		mode = override
	}
	switch mode {
	case SuccessModeAckOnPersist, SuccessModeWriteAccepted:
		return mode, nil
	default:
		return "", fmt.Errorf("%w: unsupported success mode %q", ErrInvalidRequest, mode)
	}
}
