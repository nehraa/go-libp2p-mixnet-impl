package hub

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

func BenchmarkHubCreateReceptor(b *testing.B) {
	mn, h1, h2 := newMockHosts(b)
	defer mn.Close()

	installDiscardHandler(h2, testProtocol)

	hub, err := New(h1, Config{ProtocolID: testProtocol, PingInterval: time.Hour})
	if err != nil {
		b.Fatal(err)
	}
	defer hub.Close()

	go func() {
		for range hub.Events() {
		}
	}()
	go func() {
		for range hub.Metrics() {
		}
	}()

	target := peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		receptor, err := hub.CreateReceptor(context.Background(), target)
		if err != nil {
			b.Fatal(err)
		}
		if err := hub.RemoveReceptor(receptor.ID()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHubOpenStream(b *testing.B) {
	mn, h1, h2 := newMockHosts(b)
	defer mn.Close()

	installDiscardHandler(h2, testProtocol)

	hub, err := New(h1, Config{ProtocolID: testProtocol, PingInterval: time.Hour})
	if err != nil {
		b.Fatal(err)
	}
	defer hub.Close()

	go func() {
		for range hub.Events() {
		}
	}()
	go func() {
		for range hub.Metrics() {
		}
	}()

	receptor, err := hub.CreateReceptor(context.Background(), peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()})
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		if err := hub.ResetStream(receptor.ID()); err != nil && err != ErrNoActiveStream {
			b.Fatal(err)
		}
		waitForNoActiveStream(b, hub, receptor.ID())
		b.StartTimer()

		waitForActiveStream(b, hub, receptor.ID(), func() {
			_ = hub.OpenStream(context.Background(), receptor.ID())
		})
	}
}

func BenchmarkHubSend(b *testing.B) {
	mn, h1, h2 := newMockHosts(b)
	defer mn.Close()

	installDiscardHandler(h2, testProtocol)

	hub, err := New(h1, Config{ProtocolID: testProtocol, PingInterval: time.Hour})
	if err != nil {
		b.Fatal(err)
	}
	defer hub.Close()

	go func() {
		for range hub.Events() {
		}
	}()
	go func() {
		for range hub.Metrics() {
		}
	}()

	receptor, err := hub.CreateReceptor(context.Background(), peer.AddrInfo{ID: h2.ID(), Addrs: h2.Addrs()})
	if err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte("x"), 512)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := receptor.Send(context.Background(), payload); err != nil {
			b.Fatal(err)
		}
	}
}
