# Hub Package

The `p2p/hub` package adds a manager-driven receptor layer on top of a single
libp2p host. A hub owns the protocol handler, lifecycle coordination, bounded
event delivery, and metrics publication. Each receptor binds one remote peer
and exposes a narrow contract for stream send/receive, transport snapshots, and
real-time state reporting.

Use this package when one libp2p node needs to manage many peer-specific
bindings while keeping all policy decisions centralized in one hub manager.

`New` refuses to start if the host already has an exact handler registered for
the configured `ProtocolID`. Callers must pick a dedicated protocol ID for hub
traffic.

## Public Surface

- `New(host, Config)`: create a hub around an existing host
- `CreateReceptor(ctx, peer.AddrInfo)`: bind a peer to a new receptor
- `OpenStream(id)`: explicitly create or recreate the receptor stream
- `ResetStream(id)`: terminate the active stream without removing the receptor
- `RemoveReceptor(id)`: remove the receptor and stop all background work
- `Snapshot(id)` / `Snapshots()`: inspect current receptor state
- `Events()`: bounded event stream for lifecycle and payload delivery
- `Metrics()`: bounded metrics stream for observability and health monitoring
- `Config.EventOverflowPolicy`: choose whether event-buffer overflow resets the
  active stream or only drops the event

See the other documents in this folder for lifecycle flow, observability, and
test coverage.
