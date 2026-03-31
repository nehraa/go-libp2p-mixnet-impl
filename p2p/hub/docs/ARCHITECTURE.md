# Architecture

## Core Model

- One `Hub` wraps one `host.Host`.
- One `Receptor` binds exactly one remote peer.
- A receptor owns at most one active stream at a time.
- The hub is the only component that manages receptor registration, stream
  handler wiring, and connection-state subscriptions.

## Runtime Components

- `hub.go`: manager lifecycle, registry, handler registration, overflow policy,
  and bounded publication
- `receptor.go`: peer binding state machine, ping loop, stream attach/detach,
  and snapshot assembly
- `events.go`: user-facing event and metrics contracts
- `snapshot.go`: stable state model exposed to callers and tests
- `config.go`: explicit configuration normalization
- `errors.go`: typed sentinel errors for predictable caller behavior

## Design Rules

- One peer maps to one receptor. Duplicate bindings are rejected.
- The hub never creates another host. It reuses the caller’s host, transports,
  peerstore, event bus, and listener port.
- Stream creation is explicit. `Send` fails fast when the receptor has no active
  stream.
- Data and lifecycle events are bounded and non-blocking. Slow consumers cannot
  stall read loops.
- Metrics travel on a separate channel from payload events so observability does
  not depend on draining the data plane.

## Snapshot Contents

Each snapshot combines local receptor counters with live connection metadata:

- peer identity and configured addresses
- transport, security protocol, and stream multiplexer
- connection counts, direction, stream counts, and open time
- RTT and latency EWMA
- byte counters and operation counters
- ping, read, write, and backpressure failure counters
- last activity, last send/receive, and last error timestamps
- transport details, including QUIC / WebTransport session state and WebRTC
  candidate-pair health when the underlying transport exposes them

This lets a hub manager make decisions without reaching into libp2p internals.
