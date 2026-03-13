# Mixnet project structure

This document is a file-by-file guide to the `mixnet/` directory. It is meant
to complement the package-level Go documentation by showing where protocol
behavior lives in the implementation.

## Top-level layout

```text
mixnet/
├── Docs/                  Narrative documentation and design notes
├── benchmarks/            Local benchmark CLI, docs, and generated output
├── ces/                   Compress-Encrypt-Shard pipeline
├── circuit/               Circuit state and circuit management
├── discovery/             Relay discovery and selection
├── relay/                 Relay-side forwarding logic
├── tests/                 Auxiliary test dashboard tooling
├── *.go                   Core mixnet runtime, packet formats, tests, and helpers
└── run_local_benchmarks.sh Convenience wrapper around the benchmark CLI
```

## Core package files

| File | Responsibility |
| --- | --- |
| `README.md` | Package-level guide that explains the public API surface, major directories, and where to find deeper narrative documentation. |
| `doc.go` | Package comment for Go documentation tooling, including the end-to-end protocol flow and major implementation areas. |
| `auth_tag.go` | Creates and verifies optional per-shard authenticity tags used to reject tampered traffic early. |
| `benchmark_exports.go` | Exports selected internal helpers to the benchmark CLI without broadening the public API contract. |
| `config.go` | Defines `MixnetConfig`, configuration defaults, validation rules, and helper accessors for derived values such as the shard reconstruction threshold. |
| `docker_failure_test.go` | Placeholder Docker-oriented failure harness kept behind the `docker_integration` build tag; the maintained container workflow lives under `tests/docker/`. |
| `errors.go` | Defines the structured `MixnetError` type and the error constructors used by the public API. |
| `failure_detection.go` | Watches established circuits, records heartbeat state, and triggers circuit failure notifications and recovery paths. |
| `key_management.go` | Manages ephemeral key material, retry policies, and graceful shutdown helpers for key lifecycle operations. |
| `large_stream_test.go` | Exercises large-payload and multi-write stream behavior across header-only, full onion, CES, and routed-session variants. |
| `metrics.go` | Records in-memory counters and timing information for circuits, shards, reconstruction, and resource usage. |
| `metrics_exporter.go` | Exposes collected metrics in a text format suitable for monitoring integrations. |
| `noise_key_exchange.go` | Performs Noise-based destination key exchange for session payload encryption. |
| `onion.go` | Builds and unwraps per-hop onion routing state used to forward traffic through the relay chain. |
| `onion_header.go` | Encodes and decodes the on-wire privacy header fields carried alongside each shard. |
| `padding.go` | Implements header padding and payload size padding strategies used to reduce traffic-analysis signals. |
| `privacy.go` | Defines privacy logging controls and the manager that applies those controls. |
| `privacy_transport.go` | Defines the transport message format, shard metadata, and destination-side shard parsing/reassembly helpers. |
| `production_sanity_test.go` | End-to-end regression suite that validates configuration, crypto, routing, discovery, circuit recovery, and stream behavior in one coordinated workflow. |
| `reconstruction_threshold_test.go` | Locks down threshold derivation and shard-reconstruction edge cases. |
| `relay_discovery.go` | Connects the main `Mixnet` runtime to the relay discovery package and optional cover-traffic helpers. |
| `resource_management.go` | Enforces relay resource limits and integrates those limits with the mixnet runtime. |
| `session_routing.go` | Defines the opt-in session-routing setup/data/close frames and helpers for base-session reuse. |
| `session_routing_test.go` | Verifies when routed-session mode is active and when the runtime should stay on the legacy path. |
| `session_crypto.go` | Encrypts and decrypts the end-to-end session payload carried inside shards. |
| `stream.go` | Provides the stream-style API exposed to applications (`OpenStream`, `AcceptStream`, `Read`, `Write`, `Close`). |
| `stream_upgrader.go` | Defines the stream upgrader abstraction used by callers that want a dedicated upgrade API. |
| `upgrader.go` | Houses the `Mixnet` runtime, connection establishment, shard scheduling, inbound reconstruction, and stream handler registration. |

## Subpackages

### `ces/`

| File | Responsibility |
| --- | --- |
| `compression.go` | Compression selection and compressor implementations. |
| `encryption.go` | Layered encryption helpers and erasure abstractions used by the CES pipeline. |
| `pipeline.go` | High-level CES pipeline configuration and construction. |
| `sharding.go` | Reed-Solomon-style sharding and shard reconstruction support. |

### `circuit/`

| File | Responsibility |
| --- | --- |
| `circuit.go` | Circuit state machine, timestamps, and simple state-transition helpers. |
| `manager.go` | Circuit construction, stream attachment, heartbeats, failure detection, and rebuilding. |

### `discovery/`

| File | Responsibility |
| --- | --- |
| `dht.go` | DHT-backed relay discovery, sampling, filtering, and selection. |

### `relay/`

| File | Responsibility |
| --- | --- |
| `handler.go` | Relay-side protocol handler, forwarding loop, payload limits, and rate-limited writes. |
| `key_exchange.go` | Relay-side Noise key exchange for establishing hop keys. |

## Benchmark and test tooling

| Path | Responsibility |
| --- | --- |
| `run_local_benchmarks.sh` | Convenience wrapper that sets defaults and launches `go run ./mixnet/benchmarks/cmd/mixnet-bench`. |
| `benchmarks/README.md` | Benchmark profiles, size sweeps, report contents, and invocation examples. |
| `benchmarks/cmd/mixnet-bench/` | Benchmark CLI entry point, scenario runner, report generator, and optional visual-proof capture. |
| `benchmarks/output/README.md` | Documents the timestamped local artifact directories written by benchmark runs. |
| `tests/README.md` | Quick map of the local and Docker sanity-test helpers. |
| `tests/run-tests-dashboard.py` | Curses dashboard for tracking `TestProductionSanity` progress. |
| `tests/docker/` | Dockerfiles, compose manifests, and wrapper script for running the package sanity suite in containers. |

`benchmarks/output/` is intentionally treated as a local scratch area. The
timestamped run directories under it are generated artifacts and are not part
of the versioned source tree.

## Documentation files

### `Docs/README/`

| File | Responsibility |
| --- | --- |
| `mixnet-readme.md` | Main package overview, protocol flow, and API-level usage guidance. |
| `ces-readme.md` | CES pipeline overview and stage-by-stage processing description. |
| `circuit-readme.md` | Circuit lifecycle, relay path construction, and recovery behavior. |
| `discovery-readme.md` | Relay discovery backends and relay selection strategies. |
| `relay-readme.md` | Relay node behavior, forwarding model, and deployment notes. |
| `project-structure.md` | This file; a map of the mixnet implementation tree. |

### `Docs/PRD/`

| File | Responsibility |
| --- | --- |
| `design.md` | End-to-end protocol design, architecture diagrams, and implementation-aligned behavior. |
| `design-deviations.md` | Differences between the original design and the current Go implementation. |
| `requirements.md` | Functional and non-functional requirements referenced throughout the implementation. |
| `configuration-reference.md` | Configuration defaults, ranges, presets, and trade-offs. |
| `implementation-additions.md` | Implementation-specific capabilities that extend the original protocol design. |

## How to read the implementation

If you are new to the codebase, the most useful order is:

1. `README.md`
2. `Docs/README/mixnet-readme.md`
3. `config.go`
4. `upgrader.go`
5. `stream.go`
6. `circuit/`, `relay/`, and `discovery/`
7. `ces/` and the packet-format helpers
8. `production_sanity_test.go` and `tests/README.md` when you want to follow the end-to-end verification path

That sequence moves from the public API to the orchestration layer and then to
the lower-level protocol machinery.
