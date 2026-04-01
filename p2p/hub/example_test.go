package hub

import (
	"context"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	mocknet "github.com/libp2p/go-libp2p/p2p/net/mock"
)

func ExampleHub() {
	const exampleProtocol = protocol.ID("/hub/example/1.0.0")

	mn, err := mocknet.FullMeshConnected(2)
	if err != nil {
		panic(err)
	}
	defer mn.Close()

	peers := mn.Peers()
	localHost := mn.Host(peers[0])
	remoteHost := mn.Host(peers[1])

	installDiscardHandler(remoteHost, exampleProtocol)

	hub, err := New(localHost, Config{
		ProtocolID:          exampleProtocol,
		EventOverflowPolicy: OverflowPolicyDrop,
	})
	if err != nil {
		panic(err)
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

	receptor, err := hub.CreateReceptor(context.Background(), peer.AddrInfo{
		ID:    remoteHost.ID(),
		Addrs: remoteHost.Addrs(),
	})
	if err != nil {
		panic(err)
	}

	if _, err := receptor.Send(context.Background(), []byte("hello")); err != nil {
		panic(err)
	}

	// Output:
}
