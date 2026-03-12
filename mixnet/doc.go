// Package mixnet implements Lib-Mix, a metadata-private stream transport for
// libp2p.
//
// Lib-Mix combines three ideas:
//   - relay discovery to find candidate forwarding peers,
//   - multi-hop circuits to hide the sender and receiver relationship, and
//   - optional Compress-Encrypt-Shard (CES) processing to distribute traffic
//     across multiple circuits with redundancy.
//
// A typical outbound flow looks like this:
//
//  1. NewMixnet validates a MixnetConfig and wires discovery, relay handling,
//     circuit management, metrics, and resource limiting.
//  2. OpenStream or Send establishes circuits to the destination peer.
//  3. Payload data is optionally compressed, session-encrypted, padded, and
//     split into shards.
//  4. Each shard is wrapped in privacy headers and forwarded over a separate
//     circuit through the relay network.
//  5. The destination collects enough shards to reconstruct the original
//     payload and exposes it through AcceptStream or the destination handler.
//
// Session-routing is an opt-in wire mode behind
// MixnetConfig.EnableSessionRouting. When disabled, the runtime keeps the
// legacy behavior where each write carries full routing/setup material. When
// enabled for header-only mode, the first use of a (base session, circuit)
// sends a setup frame and later writes send lighter session-data frames until
// SessionRouteIdleTimeout expires or the stream closes. Full onion continues to
// use the legacy per-frame onion path.
//
// The package is intentionally organized around those stages:
//
//   - config.go defines MixnetConfig and its privacy/performance knobs.
//   - session_routing.go defines the opt-in setup/data/close wire frames.
//   - upgrader.go coordinates connection establishment and shard delivery.
//   - stream.go exposes a familiar io.ReadWriteCloser-style stream interface.
//   - privacy_transport.go, onion.go, onion_header.go, padding.go, and
//     session_crypto.go implement the packet formats and cryptographic helpers.
//   - relay_discovery.go and discovery/ select relay candidates.
//   - circuit/ builds and maintains circuits.
//   - relay/ implements zero-knowledge forwarding on relay nodes.
//   - ces/ implements optional compression, encryption, and sharding stages.
//
// For narrative documentation and design notes, see the markdown documents in
// the mixnet/Docs directory and the package README in mixnet/README.md.
package mixnet
