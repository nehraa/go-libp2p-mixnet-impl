package upload

import (
	"context"
	"fmt"

	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/routing"
	"github.com/libp2p/go-libp2p/mixnet/discovery"
	mh "github.com/multiformats/go-multihash"
)

var encodeMultihash = mh.Encode

// DiscoveryPeerResolver resolves upload peers from explicit input or routing providers.
type DiscoveryPeerResolver struct {
	host             host.Host
	routing          routing.Routing
	namespace        string
	selectionMode    string
	samplingSize     int
	randomnessFactor float64
}

// NewDiscoveryPeerResolver constructs a resolver backed by routing providers and
// mixnet/discovery relay selection.
func NewDiscoveryPeerResolver(
	h host.Host,
	r routing.Routing,
	namespace string,
	selectionMode string,
	samplingSize int,
	randomnessFactor float64,
) *DiscoveryPeerResolver {
	return &DiscoveryPeerResolver{
		host:             h,
		routing:          r,
		namespace:        namespace,
		selectionMode:    selectionMode,
		samplingSize:     samplingSize,
		randomnessFactor: randomnessFactor,
	}
}

// ResolvePeers returns peers for one upload operation.
func (r *DiscoveryPeerResolver) ResolvePeers(ctx context.Context, req PeerResolveRequest) ([]peer.AddrInfo, error) {
	if req.Required <= 0 {
		return nil, fmt.Errorf("%w: required peer count must be positive", ErrInvalidRequest)
	}
	if len(req.Explicit) > 0 {
		if len(req.Explicit) != req.Required {
			return nil, fmt.Errorf(
				"%w: explicit peer count %d does not match required %d",
				ErrInvalidRequest,
				len(req.Explicit),
				req.Required,
			)
		}
		return dedupeAddrInfos(req.Explicit), nil
	}
	if r.routing == nil {
		return nil, fmt.Errorf("%w: no routing backend", ErrResolverUnavailable)
	}

	namespace := r.namespace
	if namespace == "" {
		namespace = string(req.ProtocolID) + defaultDiscoverySuffix
	}
	c, err := cidFromNamespace(namespace)
	if err != nil {
		return nil, err
	}
	providers := collectProviders(r.routing.FindProvidersAsync(ctx, c, 0))
	providers = discovery.FilterByExclusion(providers, req.LocalPeer)
	providers = dedupeAddrInfos(providers)
	if len(providers) < req.Required {
		return nil, fmt.Errorf(
			"%w: discovered %d peers, need %d",
			ErrInsufficientPeers,
			len(providers),
			req.Required,
		)
	}

	rd := discovery.NewRelayDiscoveryWithHost(
		r.host,
		string(req.ProtocolID),
		r.samplingSize,
		r.selectionMode,
		r.randomnessFactor,
	)
	selected, err := rd.SelectRelaysForCircuit(ctx, providers, req.Required, r.randomnessFactor)
	if err != nil {
		return nil, fmt.Errorf("select upload peers: %w", err)
	}
	out := make([]peer.AddrInfo, 0, len(selected))
	for _, relay := range selected {
		out = append(out, relay.AddrInfo)
	}
	return dedupeAddrInfos(out), nil
}

func collectProviders(ch <-chan peer.AddrInfo) []peer.AddrInfo {
	providers := make([]peer.AddrInfo, 0, 16)
	for info := range ch {
		if info.ID == "" || len(info.Addrs) == 0 {
			continue
		}
		providers = append(providers, info)
	}
	return providers
}

func dedupeAddrInfos(peers []peer.AddrInfo) []peer.AddrInfo {
	seen := make(map[peer.ID]struct{}, len(peers))
	out := make([]peer.AddrInfo, 0, len(peers))
	for _, p := range peers {
		if p.ID == "" || len(p.Addrs) == 0 {
			continue
		}
		if _, ok := seen[p.ID]; ok {
			continue
		}
		seen[p.ID] = struct{}{}
		out = append(out, p)
	}
	return out
}

func cidFromNamespace(namespace string) (cid.Cid, error) {
	hash, err := encodeMultihash([]byte(namespace), mh.SHA2_256)
	if err != nil {
		return cid.Undef, fmt.Errorf("encode discovery namespace: %w", err)
	}
	return cid.NewCidV1(cid.Raw, hash), nil
}
