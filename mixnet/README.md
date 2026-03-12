# Lib-Mix package guide

`mixnet/` contains the implementation of the Lib-Mix protocol for `go-libp2p`.
The package is designed to feel like other libp2p transports and protocol
adapters: the public API is centered around configuration, construction, and a
stream-like interface, while the lower-level packages handle relay discovery,
circuit lifecycle, and packet processing.

## What the package does

Lib-Mix adds metadata privacy to libp2p streams by routing traffic through
multiple relays and, when enabled, splitting a payload into several shards that
travel over independent circuits.

At a high level:

1. `NewMixnet` validates configuration and initializes the supporting
   subsystems.
2. `EstablishConnection`, `OpenStream`, or `Send` discovers relays and builds
   parallel circuits to the destination.
3. Payload data is optionally compressed, encrypted, padded, and sharded.
4. Relays forward only what they need to know for the next hop.
5. The destination reconstructs the payload and exposes it through
   `AcceptStream` or the destination-side session channel.

## Session-routing mode

The package supports an opt-in wire mode controlled by
`MixnetConfig.EnableSessionRouting`.

- `EnableSessionRouting=false` keeps the legacy behavior. Each write or
  `SendWithSession` call carries the full routing/setup material needed for
  that message.
- `EnableSessionRouting=true` switches to a setup-once/data-later protocol.
  In the current implementation this optimization is used by the header-only
  transport path. The first use of a `(baseSessionID, circuitID)` sends a
  setup frame. Later header-only writes on that same base session send smaller
  session-data frames that reuse cached route and session state. Full onion
  stays on the legacy per-frame onion path.
- `SessionRouteIdleTimeout` controls how long sender, relay, and destination
  keep routed-session state alive when no more data arrives. The default is
  `30s`.

The new mode is implemented entirely inside `mixnet/` and is off by default,
so existing callers keep the old wire behavior unless they enable it
explicitly.

## Header-only streaming behavior

The current header-only transport path is implemented as a streaming fast path,
not a buffered rewrite at every hop.

- The sender builds the outbound header-only wire frame once.
- Each intermediate relay decrypts only the onion header needed to learn the
  next hop.
- The remaining payload bytes are streamed from the inbound relay stream to the
  outbound stream in chunks.
- Intermediate relays do not allocate and rebuild a second full copy of the
  shard payload on every hop.
- The destination still buffers and reconstructs the payload as part of normal
  session delivery.

This matters for large transfers: the main performance win of `header-only`
mode is not just reduced per-hop crypto, but also avoiding repeated full-payload
copying at relay hops.

## Security model for routed sessions

Session-routing does not turn relays into destination-aware forwarders. A relay
stores route state per inbound authenticated libp2p stream and per
`baseSessionID`, then reuses that cached next-hop or final-hop state for later
header-only session-data frames.

- Off-path network attackers cannot inject bytes into an established relay
  stream. The adjacent libp2p hop is already on an authenticated encrypted
  connection.
- A malicious adjacent relay can still send bogus routed data for a known base
  session in this v1. Relays do not yet verify an additional per-hop routed
  data MAC before forwarding.
- The destination still verifies end-to-end session crypto and optional auth
  tags, so forged or modified data should be rejected there.

## Directory structure

| Path | Purpose |
| --- | --- |
| `config.go` | Mixnet configuration, defaults, validation, and derived values. |
| `session_routing.go` | Setup/data/close frame definitions for the opt-in session-routing mode. |
| `upgrader.go` | Core `Mixnet` type and end-to-end send/receive orchestration. |
| `stream.go` | Stream-oriented API (`OpenStream`, `AcceptStream`, `Read`, `Write`, `Close`). |
| `privacy_transport.go` | Privacy packet format used between origin, relays, and destination. |
| `onion.go` / `onion_header.go` | Onion header construction, layered encryption, and header parsing. |
| `padding.go` / `auth_tag.go` | Size-hiding padding and optional shard authenticity tags. |
| `session_crypto.go` / `noise_key_exchange.go` / `key_management.go` | Session payload encryption and Noise-based key exchange helpers. |
| `relay_discovery.go` / `discovery/` | Relay discovery, sampling, and selection. |
| `circuit/` | Circuit state, circuit construction, heartbeats, and recovery. |
| `relay/` | Relay-side forwarding handlers and relay key exchange. |
| `ces/` | Optional Compress-Encrypt-Shard pipeline implementation. |
| `metrics*.go` / `resource_management.go` / `failure_detection.go` | Operations, observability, and runtime protections. |
| `Docs/` | Narrative protocol, configuration, and component documentation. |

## Documentation map

The markdown documentation in `mixnet/Docs` is split into two groups:

- `Docs/README/`: implementation-facing guides for the main package and
  subpackages.
- `Docs/PRD/`: design, requirement, and configuration documents aligned to the
  current implementation.

Useful starting points:

- `Docs/README/mixnet-readme.md`: protocol overview and usage.
- `Docs/README/project-structure.md`: file-by-file map of the mixnet folder.
- `Docs/PRD/design.md`: end-to-end design and protocol walkthrough.
- `Docs/PRD/configuration-reference.md`: configuration defaults and trade-offs.

## Public API entry points

- Import path: `github.com/libp2p/go-libp2p/mixnet`
- `DefaultConfig` / `NewMixnetConfig`: create configuration.
- `DefaultRetryConfig` / `RetryWithBackoff`: retry helpers for transient failures.
- `NewMixnet`: construct the runtime.
- `NewStreamUpgrader`: wrap a `Mixnet` as a libp2p-friendly stream upgrader.
- `NewMixnetWithKeyManagement`: add retry, graceful-close, and key-management helpers.
- `NewMixnetWithResources`: add relay resource enforcement using `ResourceConfig`.
- `DefaultResourceConfig`: create the optional resource-limits configuration.
- `OpenStream`: create an outbound stream-like session to a destination peer.
- `AcceptStream`: wait for an inbound session.
- `Send`: send a payload without manually managing a stream wrapper.
- `SendWithSession`: reuse a caller-chosen base session ID across multiple
  sends.
- `DiscoverRelaysWithVerification` / `UseDiscoveryService`: lower-level relay discovery helpers.
- `DefaultCoverTrafficConfig` / `NewCoverTrafficGenerator`: optional cover-traffic helpers.
- `Metrics`, `MetricsHandler`, `StartMetricsEndpoint`: observe runtime behavior.
- `ProtocolID`: the public libp2p protocol ID when you need to wire handlers or verify support manually.

There is no `main.go` entry point for embedding mixnet into another libp2p
application. Mixnet is a library package: applications import `mixnet`,
construct a `Mixnet` with `NewMixnet`, and configure hops, circuits, and flags
through `MixnetConfig`. The `main.go` under
`mixnet/benchmarks/cmd/mixnet-bench/` is only the benchmark CLI.

All optional settings and customization go through `MixnetConfig`, including:
`HopCount`, `CircuitCount`, `Compression`, `ErasureThreshold`,
`UseCESPipeline`, `UseCSE`, `EncryptionMode`, `SelectionMode`,
`SamplingSize`, `RandomnessFactor`, `EnableSessionRouting`,
`SessionRouteIdleTimeout`, `HeaderPaddingEnabled`, `HeaderPaddingMin`,
`HeaderPaddingMax`, `PayloadPaddingStrategy`, `PayloadPaddingMin`,
`PayloadPaddingMax`, `PayloadPaddingBuckets`, `EnableAuthTag`,
`AuthTagSize`, and `MaxJitter`.

`DefaultConfig` gives a ready-to-use baseline. `NewMixnetConfig` is the manual
construction path: it clears most fields back to zero values so callers can set
everything explicitly and then optionally call `InitDefaults` before
validation. After circuits are established, the runtime locks the config; the
setter helpers then return `ErrConfigImmutable`.

For lower-level details, consult the Go doc comments in the package and the
supporting documents linked above.
