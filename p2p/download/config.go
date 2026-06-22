package download

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/libp2p/go-libp2p/core/protocol"
	mixnet "github.com/libp2p/go-libp2p/mixnet/core"
	"github.com/libp2p/go-libp2p/p2p/hub"
)

const (
	defaultProtocolID     = protocol.ID("/libp2p/download/1.0.0")
	defaultChunkSize      = 64 * 1024
	defaultMaxFrameSize   = 8 * 1024 * 1024
	defaultMaxConcurrency = 16
	defaultSendTimeout    = 20 * time.Second
	defaultReceiveTimeout = 45 * time.Second
	defaultRetryCount     = 1
	defaultRetryBackoff   = 250 * time.Millisecond
	defaultDownloadRoot   = "download_data"
	defaultHolderRoot     = "upload_data"
)

// Config controls downloader and holder behavior.
type Config struct {
	ProtocolID protocol.ID
	HubConfig  hub.Config

	ChunkSize    int
	MaxFrameSize int

	MaxConcurrency int
	SendTimeout    time.Duration
	ReceiveTimeout time.Duration
	RetryCount     int
	RetryBackoff   time.Duration

	DownloadRoot string
	HolderRoot   string

	Reconstructor ThresholdReconstructor
	ShardProvider ShardProvider
}

func normalizeConfig(cfg Config) (Config, error) {
	if cfg.ProtocolID == "" {
		cfg.ProtocolID = defaultProtocolID
	}
	cfg.HubConfig.ProtocolID = cfg.ProtocolID

	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = defaultChunkSize
	}
	if cfg.MaxFrameSize <= 0 {
		cfg.MaxFrameSize = defaultMaxFrameSize
	}
	if cfg.MaxConcurrency <= 0 {
		cfg.MaxConcurrency = defaultMaxConcurrency
	}
	if cfg.SendTimeout <= 0 {
		cfg.SendTimeout = defaultSendTimeout
	}
	if cfg.ReceiveTimeout <= 0 {
		cfg.ReceiveTimeout = defaultReceiveTimeout
	}
	if cfg.RetryCount < 0 {
		return Config{}, fmt.Errorf("%w: retry count cannot be negative", ErrInvalidConfig)
	}
	if cfg.RetryBackoff < 0 {
		return Config{}, fmt.Errorf("%w: retry backoff cannot be negative", ErrInvalidConfig)
	}
	if cfg.RetryCount == 0 {
		cfg.RetryCount = defaultRetryCount
	}
	if cfg.RetryBackoff == 0 {
		cfg.RetryBackoff = defaultRetryBackoff
	}
	if cfg.DownloadRoot == "" {
		cfg.DownloadRoot = defaultDownloadRoot
	}
	if cfg.HolderRoot == "" {
		cfg.HolderRoot = defaultHolderRoot
	}
	cfg.DownloadRoot = filepath.Clean(cfg.DownloadRoot)
	cfg.HolderRoot = filepath.Clean(cfg.HolderRoot)

	if cfg.ChunkSize+128 > cfg.MaxFrameSize {
		return Config{}, fmt.Errorf("%w: chunk size %d too large for max frame size %d", ErrInvalidConfig, cfg.ChunkSize, cfg.MaxFrameSize)
	}

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

func effectiveMode(requestMode ReconstructionMode) (ReconstructionMode, error) {
	mode := requestMode
	if mode == "" {
		mode = ReconstructionModeStrict
	}
	switch mode {
	case ReconstructionModeStrict, ReconstructionModeThreshold, ReconstructionModeBestEffort:
		return mode, nil
	default:
		return "", fmt.Errorf("%w: unsupported reconstruction mode %q", ErrInvalidRequest, mode)
	}
}
