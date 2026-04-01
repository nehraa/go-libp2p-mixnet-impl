# Observability

## Event Channel

`Events()` is for payload and lifecycle signals:

- receptor created / removed
- stream opened / closed
- data received
- peer offline
- operational errors

This channel is intentionally bounded. It is part of the live data plane and is
allowed to reject slow consumers instead of blocking stream readers.

## Metrics Channel

`Metrics()` is the dedicated observability channel. It publishes snapshots for:

- receptor creation and removal
- stream open and close
- first packet arrival
- ping success and failure
- connect and stream-open failures
- read and write failures
- dropped events and backpressure resets

This channel is also bounded, but overflow only increments counters and logs a
warning because metrics loss should not break the data path.

`backpressure_reset` metrics are only emitted when `Config.EventOverflowPolicy`
is `OverflowPolicyResetStream`. In drop-only mode the hub still emits
`event_dropped`, but it keeps the stream open.

## Logging

The package emits structured logs for:

- hub start and stop
- receptor create and remove
- stream open and close failures
- connect failures
- ping failures
- event-buffer and metrics-buffer saturation
- peer disconnect transitions

Use hub logs together with snapshots and metrics updates to diagnose transport
selection, reconnection churn, consumer backpressure, and transport-specific
state such as QUIC resumption or WebRTC selected candidate pairs.
