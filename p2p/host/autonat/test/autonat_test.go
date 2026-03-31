// This separate testing package helps to resolve a circular dependency potentially
// being created between libp2p and libp2p-autonat
package autonattest

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/p2p/host/autonat"
	"github.com/multiformats/go-multiaddr"

	"github.com/stretchr/testify/require"
)

func TestAutonatRoundtrip(t *testing.T) {
	// 3 hosts are used: [client] and [service + dialback dialer]
	client, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	require.NoError(t, err)
	defer client.Close()
	service, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	require.NoError(t, err)
	defer service.Close()
	dialback, err := libp2p.New(libp2p.NoListenAddrs)
	require.NoError(t, err)
	defer dialback.Close()
	if _, err := autonat.New(service, autonat.EnableService(dialback.Network())); err != nil {
		t.Fatal(err)
	}

	client.Peerstore().AddAddrs(service.ID(), service.Addrs(), time.Hour)
	client.Peerstore().AddProtocols(service.ID(), autonat.AutoNATProto)
	require.NoError(t, client.Connect(context.Background(), service.Peerstore().PeerInfo(service.ID())))

	probeAddrs := []multiaddr.Multiaddr{multiaddr.StringCast("/ip4/203.0.113.1/tcp/4001")}
	err = autonat.NewAutoNATClient(client, func() []multiaddr.Multiaddr {
		return probeAddrs
	}, nil).DialBack(context.Background(), service.ID())
	require.Error(t, err)
	require.True(t, autonat.IsDialRefused(err), "expected dialback refusal, got %v", err)
}
