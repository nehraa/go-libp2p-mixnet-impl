package upload

import (
	"context"
	"errors"
	"testing"

	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/routing"
	ma "github.com/multiformats/go-multiaddr"
)

func TestResolvePeersRejectsNonPositiveRequired(t *testing.T) {
	resolver := &DiscoveryPeerResolver{}

	_, err := resolver.ResolvePeers(context.Background(), PeerResolveRequest{})
	if err == nil {
		t.Fatal("expected required peer count validation error")
	}
}

func TestResolvePeersRejectsExplicitPeerCountMismatch(t *testing.T) {
	resolver := &DiscoveryPeerResolver{}

	_, err := resolver.ResolvePeers(context.Background(), PeerResolveRequest{
		Required: 2,
		Explicit: []peer.AddrInfo{{ID: "peer-1"}, {ID: "peer-2"}, {ID: "peer-3"}},
	})
	if err == nil {
		t.Fatal("expected explicit peer count mismatch error")
	}
}

func TestResolvePeersRejectsMissingRoutingBackend(t *testing.T) {
	resolver := &DiscoveryPeerResolver{}

	_, err := resolver.ResolvePeers(context.Background(), PeerResolveRequest{
		Required:   1,
		ProtocolID: "/upload/test",
	})
	if err == nil {
		t.Fatal("expected missing routing backend error")
	}
}

func TestResolvePeersRejectsInsufficientProviders(t *testing.T) {
	resolver := &DiscoveryPeerResolver{
		routing: &discoveryRoutingStub{
			providers: []peer.AddrInfo{
				{ID: "peer-1", Addrs: []ma.Multiaddr{ma.StringCast("/ip4/127.0.0.1/tcp/10001")}},
			},
		},
	}

	_, err := resolver.ResolvePeers(context.Background(), PeerResolveRequest{
		Required:   2,
		ProtocolID: "/upload/test",
	})
	if err == nil {
		t.Fatal("expected insufficient peers error")
	}
}

func TestCollectProvidersFiltersInvalidEntries(t *testing.T) {
	input := make(chan peer.AddrInfo, 4)
	input <- peer.AddrInfo{}
	input <- peer.AddrInfo{ID: "peer-1", Addrs: []ma.Multiaddr{ma.StringCast("/ip4/127.0.0.1/tcp/10001")}}
	input <- peer.AddrInfo{ID: "peer-2"}
	input <- peer.AddrInfo{ID: "peer-3", Addrs: []ma.Multiaddr{ma.StringCast("/ip4/127.0.0.1/tcp/10003")}}
	close(input)

	got := collectProviders(input)
	if len(got) != 2 {
		t.Fatalf("expected 2 valid providers, got %d", len(got))
	}
}

func TestDedupeAddrInfosRemovesDuplicates(t *testing.T) {
	peers := []peer.AddrInfo{
		{ID: "peer-1", Addrs: []ma.Multiaddr{ma.StringCast("/ip4/127.0.0.1/tcp/10001")}},
		{ID: "peer-1", Addrs: []ma.Multiaddr{ma.StringCast("/ip4/127.0.0.1/tcp/10001")}},
		{ID: "peer-2", Addrs: []ma.Multiaddr{ma.StringCast("/ip4/127.0.0.1/tcp/10002")}},
		{ID: "", Addrs: []ma.Multiaddr{ma.StringCast("/ip4/127.0.0.1/tcp/10003")}},
	}

	got := dedupeAddrInfos(peers)
	if len(got) != 2 {
		t.Fatalf("expected 2 deduped peers, got %d", len(got))
	}
}

func TestCidFromNamespaceReturnsErrorWhenEncodingFails(t *testing.T) {
	original := encodeMultihash
	encodeMultihash = func([]byte, uint64) ([]byte, error) {
		return nil, errors.New("encode failed")
	}
	defer func() {
		encodeMultihash = original
	}()

	_, err := cidFromNamespace("/upload/test")
	if err == nil {
		t.Fatal("expected encode error")
	}
}

func TestCidFromNamespaceReturnsCid(t *testing.T) {
	got, err := cidFromNamespace("/upload/test")
	if err != nil {
		t.Fatalf("cid from namespace: %v", err)
	}
	if !got.Defined() {
		t.Fatal("expected defined cid")
	}
}

type discoveryRoutingStub struct {
	providers []peer.AddrInfo
}

func (s *discoveryRoutingStub) Provide(context.Context, cid.Cid, bool) error { return nil }

func (s *discoveryRoutingStub) FindProvidersAsync(context.Context, cid.Cid, int) <-chan peer.AddrInfo {
	ch := make(chan peer.AddrInfo, len(s.providers))
	for _, provider := range s.providers {
		ch <- provider
	}
	close(ch)
	return ch
}

func (s *discoveryRoutingStub) FindPeer(context.Context, peer.ID) (peer.AddrInfo, error) {
	return peer.AddrInfo{}, errors.New("not implemented")
}

func (s *discoveryRoutingStub) PutValue(context.Context, string, []byte, ...routing.Option) error {
	return nil
}

func (s *discoveryRoutingStub) GetValue(context.Context, string, ...routing.Option) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (s *discoveryRoutingStub) SearchValue(context.Context, string, ...routing.Option) (<-chan []byte, error) {
	ch := make(chan []byte)
	close(ch)
	return ch, nil
}

func (s *discoveryRoutingStub) Bootstrap(context.Context) error { return nil }
