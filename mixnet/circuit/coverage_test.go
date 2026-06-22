package circuit

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
)

func TestCircuitStateAndManagerHelpers(t *testing.T) {
	t.Parallel()

	circuitID := "circuit-1"
	c := NewCircuit(circuitID, []peer.ID{"entry", "middle", "exit"})
	if got := c.GetState(); got != StatePending {
		t.Fatalf("GetState() = %s, want pending", got)
	}
	if got := c.Entry(); got != "entry" {
		t.Fatalf("Entry() = %s, want entry", got)
	}
	if got := c.Exit(); got != "exit" {
		t.Fatalf("Exit() = %s, want exit", got)
	}
	c.SetState(StateActive)
	if !c.IsActive() {
		t.Fatal("IsActive() should report active")
	}
	c.SetLastHeartbeat(time.Now())
	if c.GetLastHeartbeat().IsZero() {
		t.Fatal("GetLastHeartbeat() should not be zero")
	}
	c.MarkFailed()
	if c.GetState() != StateFailed || c.FailureCount != 1 {
		t.Fatalf("MarkFailed() did not transition correctly: %+v", c)
	}
	if got := StateClosed.String(); got != "closed" {
		t.Fatalf("StateClosed.String() = %q, want closed", got)
	}
	if got := CircuitState(99).String(); got != "unknown" {
		t.Fatalf("unknown state string = %q", got)
	}

	mgr := NewCircuitManager(&CircuitConfig{
		HopCount:      2,
		CircuitCount:  2,
		StreamTimeout: time.Second,
	})
	mgr.UpdateRelayPool([]RelayInfo{
		{PeerID: "relay-a"},
		{PeerID: "relay-b"},
		{PeerID: "relay-c"},
		{PeerID: "relay-d"},
	})
	mgr.circuits[circuitID] = c
	if got := mgr.Config(); got != mgr.cfg {
		t.Fatal("Config() did not return manager config")
	}
	if got, ok := mgr.GetCircuit(circuitID); !ok || got != c {
		t.Fatal("GetCircuit() did not return stored circuit")
	}
	if got := mgr.ListCircuits(); len(got) != 1 {
		t.Fatalf("ListCircuits() len = %d, want 1", len(got))
	}
	if got, err := mgr.GetRelaysForCircuit(circuitID); err != nil || len(got) != 3 {
		t.Fatalf("GetRelaysForCircuit() = %v, %v", got, err)
	}
	mgr.MarkCircuitFailed(circuitID)
	if !mgr.DetectFailure(circuitID) {
		t.Fatal("DetectFailure() should report failed circuit")
	}
	if got := mgr.ActiveCircuitCount(); got != 0 {
		t.Fatalf("ActiveCircuitCount() = %d, want 0", got)
	}
	if mgr.CanRecover() {
		t.Fatal("CanRecover() should be false without active circuits")
	}
	if got := mgr.RecoveryCapacity(); got != -1 {
		t.Fatalf("RecoveryCapacity() = %d, want -1", got)
	}

	mgr.EnableAdaptiveScaling(1, 4, 0)
	if !mgr.cfg.AdaptiveScalingEnabled || mgr.cfg.AdaptiveScalingStep != 1 {
		t.Fatalf("EnableAdaptiveScaling() did not normalize config: %+v", mgr.cfg)
	}
	if got := maxInt(2, 7); got != 7 {
		t.Fatalf("maxInt() = %d, want 7", got)
	}
}

func TestCircuitManagerLifecycleAndRecovery(t *testing.T) {
	t.Parallel()

	mgr := NewCircuitManager(&CircuitConfig{
		HopCount:      2,
		CircuitCount:  2,
		StreamTimeout: 50 * time.Millisecond,
	})
	mgr.UpdateRelayPool([]RelayInfo{
		{PeerID: "relay-a"},
		{PeerID: "relay-b"},
		{PeerID: "relay-c"},
		{PeerID: "relay-d"},
		{PeerID: "relay-e"},
		{PeerID: "relay-f"},
	})

	circuit := NewCircuit("circuit-2", []peer.ID{"relay-a", "relay-b"})
	circuit.SetState(StateActive)
	circuit.SetLastHeartbeat(time.Now().Add(-2 * time.Second))
	mgr.circuits[circuit.ID] = circuit
	activePeer := NewCircuit("active", []peer.ID{"relay-c", "relay-d"})
	activePeer.SetState(StateActive)
	mgr.circuits[activePeer.ID] = activePeer

	mgr.StartHeartbeat(circuit.ID, time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if mgr.circuits[circuit.ID].GetLastHeartbeat().IsZero() {
		t.Fatal("StartHeartbeat() did not set last heartbeat")
	}

	mgr.circuits["failed"] = NewCircuit("failed", []peer.ID{"relay-a", "relay-c"})
	mgr.circuits["failed"].SetState(StateFailed)
	rebuilt, err := mgr.RebuildCircuit("failed")
	if err != nil {
		t.Fatalf("RebuildCircuit() error = %v", err)
	}
	if rebuilt == nil || rebuilt.GetState() != StateBuilding {
		t.Fatal("RebuildCircuit() did not create a building circuit")
	}

	if _, err := mgr.BuildCircuit(); err != nil {
		t.Fatalf("BuildCircuit() error = %v", err)
	}

	if err := mgr.ActivateCircuit(circuit.ID); err != nil {
		t.Fatalf("ActivateCircuit() error = %v", err)
	}
	if !mgr.CanRecover() {
		t.Fatal("CanRecover() should report true once circuits are active")
	}
	if mgr.RecoveryCapacity() < 0 {
		t.Fatal("RecoveryCapacity() should be non-negative with active circuits")
	}

	if err := mgr.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if mgr.circuits[circuit.ID].GetState() != StateClosed {
		t.Fatal("Close() did not close tracked circuits")
	}
}

func TestCircuitManagerStreamOperationsWithLocalHosts(t *testing.T) {
	origin, err := libp2p.New()
	if err != nil {
		t.Fatalf("libp2p.New(origin) error = %v", err)
	}
	t.Cleanup(func() { _ = origin.Close() })

	relayHost, err := libp2p.New()
	if err != nil {
		t.Fatalf("libp2p.New(relay) error = %v", err)
	}
	t.Cleanup(func() { _ = relayHost.Close() })

	protoID := protocol.ID("/mixnet/circuit-test/1.0.0")
	sendCh := make(chan []byte, 1)
	relayHost.SetStreamHandler(protoID, func(s network.Stream) {
		defer s.Close()
		data, _ := io.ReadAll(s)
		sendCh <- data
	})

	mgr := NewCircuitManager(&CircuitConfig{
		HopCount:      1,
		CircuitCount:  1,
		StreamTimeout: time.Second,
	})
	mgr.SetHost(origin)
	origin.Peerstore().AddAddrs(relayHost.ID(), relayHost.Addrs(), peerstore.PermanentAddrTTL)
	circuit := NewCircuit("circuit-3", []peer.ID{relayHost.ID()})
	if err := mgr.EstablishCircuit(circuit, peer.ID("destination"), string(protoID)); err != nil {
		t.Fatalf("EstablishCircuit() error = %v", err)
	}
	if _, ok := mgr.GetStream(circuit.ID); !ok {
		t.Fatal("GetStream() should return established stream")
	}

	if err := mgr.SendData(circuit.ID, []byte("hello")); err != nil {
		t.Fatalf("SendData() error = %v", err)
	}
	if err := mgr.SendDataParts(circuit.ID, []byte(" mix"), []byte("net")); err != nil {
		t.Fatalf("SendDataParts() error = %v", err)
	}
	if err := mgr.CloseCircuit(circuit.ID); err != nil {
		t.Fatalf("CloseCircuit() error = %v", err)
	}

	received := <-sendCh
	if !bytes.Equal(received, []byte("hello mixnet")) {
		t.Fatalf("relay received %q, want %q", received, []byte("hello mixnet"))
	}

	echoHost, err := libp2p.New()
	if err != nil {
		t.Fatalf("libp2p.New(echo) error = %v", err)
	}
	t.Cleanup(func() { _ = echoHost.Close() })
	echoHost.SetStreamHandler(protoID, func(s network.Stream) {
		defer s.Close()
		_, _ = s.Write([]byte("pong"))
	})
	origin.Peerstore().AddAddrs(echoHost.ID(), echoHost.Addrs(), peerstore.PermanentAddrTTL)
	echoCircuit := NewCircuit("circuit-4", []peer.ID{echoHost.ID()})
	if err := mgr.EstablishCircuit(echoCircuit, peer.ID("destination"), string(protoID)); err != nil {
		t.Fatalf("EstablishCircuit(echo) error = %v", err)
	}
	buf := make([]byte, 4)
	if n, err := mgr.ReadData(echoCircuit.ID, buf); string(buf[:n]) != "pong" || (err != nil && err != io.EOF) {
		t.Fatalf("ReadData() = (%d, %q, %v), want pong", n, buf[:n], err)
	}
	if err := mgr.CloseCircuitWithContext(context.Background(), echoCircuit.ID); err != nil {
		t.Fatalf("CloseCircuitWithContext() error = %v", err)
	}
}
