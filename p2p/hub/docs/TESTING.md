# Testing Strategy

The package uses multiple test layers because one layer is not enough for a
network manager.

## Mocknet Integration

`hub_test.go` and `observability_test.go` cover:

- duplicate binding rejection
- stream reset and receptor removal
- first-packet notification
- offline handling
- bounded event and metrics behavior
- failure accounting

These tests are deterministic and fast.

## Deterministic Simnet

`hub_synctest_test.go` validates ping-driven RTT sampling with controlled
latency. This prevents timing noise from hiding regressions in the metrics path.

## Real Transport Matrix

`transport_integration_test.go` exercises the hub against real libp2p hosts on:

- TCP
- QUIC
- WebSocket
- WebTransport
- WebRTC Direct

The assertions verify transport metadata, connection snapshots, and successful
payload delivery.

## Subprocess End-To-End

`subprocess_e2e_test.go` starts a real remote peer from a fresh process and
connects to it from the test process across:

- TCP
- QUIC
- WebSocket
- WebTransport
- WebRTC Direct

This closes the gap between in-process integration tests and true startup-time
orchestration.
