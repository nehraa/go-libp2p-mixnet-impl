package download

import (
	"context"
	"fmt"
	"io"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/routing"
	mixnet "github.com/libp2p/go-libp2p/mixnet/core"
	"github.com/libp2p/go-libp2p/p2p/hub"
)

type mixnetStream interface {
	io.ReadWriteCloser
}

type mixnetRuntime interface {
	OpenStream(ctx context.Context, dest peer.ID) (mixnetStream, error)
	AcceptStream(ctx context.Context) (mixnetStream, error)
	Close() error
}

type mixnetAdapter struct {
	inner *mixnet.Mixnet
}

var newMixnetRuntimeFactory = func(cfg *mixnet.MixnetConfig, h host.Host, r routing.Routing) (mixnetRuntime, error) {
	inner, err := mixnet.NewMixnet(cfg, h, r)
	if err != nil {
		return nil, err
	}
	return &mixnetAdapter{inner: inner}, nil
}

func (a *mixnetAdapter) OpenStream(ctx context.Context, dest peer.ID) (mixnetStream, error) {
	return a.inner.OpenStream(ctx, dest)
}

func (a *mixnetAdapter) AcceptStream(ctx context.Context) (mixnetStream, error) {
	return a.inner.AcceptStream(ctx)
}

func (a *mixnetAdapter) Close() error {
	return a.inner.Close()
}

func createMixnetRuntime(h host.Host, r routing.Routing, cfg hub.Config) (mixnetRuntime, error) {
	if !cfg.Mixnet.Enabled {
		return nil, nil
	}
	if h == nil {
		return nil, fmt.Errorf("%w: host is required", ErrInvalidConfig)
	}
	if r == nil {
		return nil, fmt.Errorf("%w: routing is required for mixnet transport", ErrInvalidConfig)
	}
	mixCfg := cfg.Mixnet.Config
	if mixCfg == nil {
		mixCfg = mixnet.DefaultConfig()
	} else {
		mixCfg = mixCfg.Clone()
		mixCfg.InitDefaults()
	}
	runtime, err := newMixnetRuntimeFactory(mixCfg, h, r)
	if err != nil {
		return nil, fmt.Errorf("create mixnet runtime: %w", err)
	}
	return runtime, nil
}
