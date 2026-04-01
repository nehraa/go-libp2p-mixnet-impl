package hub

import (
	"testing"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
)

func waitForMetric(t testing.TB, metrics <-chan MetricUpdate, timeout time.Duration, predicate func(MetricUpdate) bool) MetricUpdate {
	t.Helper()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case update, ok := <-metrics:
			if !ok {
				t.Fatal("metrics channel closed before expected metric")
			}
			if predicate(update) {
				return update
			}
		case <-timer.C:
			t.Fatal("timed out waiting for metric")
		}
	}
}

func ensureNoMetric(t testing.TB, metrics <-chan MetricUpdate, timeout time.Duration, predicate func(MetricUpdate) bool) {
	t.Helper()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case update, ok := <-metrics:
			if !ok {
				return
			}
			if predicate(update) {
				t.Fatalf("unexpected metric received: %#v", update)
			}
		case <-timer.C:
			return
		}
	}
}

func drainEvents(events <-chan Event) {
	for {
		select {
		case <-events:
		default:
			return
		}
	}
}

func drainMetrics(metrics <-chan MetricUpdate) {
	for {
		select {
		case <-metrics:
		default:
			return
		}
	}
}

func newRealHost(t testing.TB, listenAddr string) host.Host {
	t.Helper()

	h, err := libp2p.New(libp2p.ListenAddrStrings(listenAddr))
	require.NoError(t, err)
	return h
}

func multiaddrsToStrings(addrs []ma.Multiaddr) []string {
	encoded := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		encoded = append(encoded, addr.String())
	}
	return encoded
}

func stringsToMultiaddrs(t testing.TB, values []string) []ma.Multiaddr {
	t.Helper()

	addrs := make([]ma.Multiaddr, 0, len(values))
	for _, value := range values {
		addr, err := ma.NewMultiaddr(value)
		require.NoError(t, err)
		addrs = append(addrs, addr)
	}
	return addrs
}
