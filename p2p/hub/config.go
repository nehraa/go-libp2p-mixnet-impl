package hub

import (
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/protocol"
)

const (
	defaultPingInterval   = 5 * time.Second
	defaultPingTimeout    = 10 * time.Second
	defaultEventBuffer    = 64
	defaultMetricsBuffer  = 128
	defaultReadBufferSize = 32 * 1024
)

// OverflowPolicy defines how the hub reacts when its event channel is full.
type OverflowPolicy string

const (
	// OverflowPolicyResetStream preserves the current default behavior by
	// resetting the active stream when a data event cannot be delivered.
	OverflowPolicyResetStream OverflowPolicy = "reset_stream"
	// OverflowPolicyDrop drops the event and keeps the active stream open.
	OverflowPolicyDrop OverflowPolicy = "drop"
)

// Config defines hub behavior.
type Config struct {
	ProtocolID          protocol.ID
	PingInterval        time.Duration
	PingTimeout         time.Duration
	EventBufferSize     int
	MetricsBufferSize   int
	ReadBufferSize      int
	EventOverflowPolicy OverflowPolicy
}

func normalizeConfig(cfg Config) (Config, error) {
	if cfg.ProtocolID == "" {
		return Config{}, fmt.Errorf("%w: protocol id is required", ErrInvalidConfig)
	}
	if cfg.PingInterval == 0 {
		cfg.PingInterval = defaultPingInterval
	}
	if cfg.PingInterval < 0 {
		return Config{}, fmt.Errorf("%w: ping interval must be positive", ErrInvalidConfig)
	}
	if cfg.PingTimeout == 0 {
		cfg.PingTimeout = defaultPingTimeout
	}
	if cfg.PingTimeout <= 0 {
		return Config{}, fmt.Errorf("%w: ping timeout must be positive", ErrInvalidConfig)
	}
	if cfg.EventBufferSize == 0 {
		cfg.EventBufferSize = defaultEventBuffer
	}
	if cfg.EventBufferSize <= 0 {
		return Config{}, fmt.Errorf("%w: event buffer size must be positive", ErrInvalidConfig)
	}
	if cfg.MetricsBufferSize == 0 {
		cfg.MetricsBufferSize = defaultMetricsBuffer
	}
	if cfg.MetricsBufferSize <= 0 {
		return Config{}, fmt.Errorf("%w: metrics buffer size must be positive", ErrInvalidConfig)
	}
	if cfg.ReadBufferSize == 0 {
		cfg.ReadBufferSize = defaultReadBufferSize
	}
	if cfg.ReadBufferSize <= 0 {
		return Config{}, fmt.Errorf("%w: read buffer size must be positive", ErrInvalidConfig)
	}
	if cfg.EventOverflowPolicy == "" {
		cfg.EventOverflowPolicy = OverflowPolicyResetStream
	}
	switch cfg.EventOverflowPolicy {
	case OverflowPolicyResetStream, OverflowPolicyDrop:
	default:
		return Config{}, fmt.Errorf("%w: unsupported event overflow policy %q", ErrInvalidConfig, cfg.EventOverflowPolicy)
	}
	return cfg, nil
}
