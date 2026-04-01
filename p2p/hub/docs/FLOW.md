# Lifecycle Flow

## Receptor Creation

1. The manager calls `CreateReceptor`.
2. The hub validates the peer binding and registers the receptor.
3. The receptor starts its ping loop.
4. The hub attempts to connect and open the initial stream.
5. Stream-open events and metrics are published.

## Data Path

1. A sender calls `Receptor.Send`.
2. The active stream writes bytes directly with no extra framing.
3. The remote side writes back or sends data on the same protocol.
4. The receptor read loop emits `data_received` events.
5. The first inbound chunk also emits a dedicated first-packet metrics update.

## Stream Loss And Recovery

1. Read or write failures detach the current stream.
2. The hub publishes close and error signals.
3. The receptor remains registered.
4. The manager decides whether to call `OpenStream` again.

## Offline Detection

1. The hub subscribes to libp2p connectedness changes.
2. When the peer becomes `NotConnected`, the active stream is cleared.
3. The hub publishes `peer_offline` and `stream_closed` state.
4. The receptor stays available for future reconnection.

## Hub Shutdown

1. The hub removes its stream handler and connectedness subscriptions.
2. Each receptor is cancelled and its active stream is reset if one exists.
3. The hub emits final `stream_closed` and `receptor_removed` signals before
   the channels close.
4. Background loops exit and the event and metrics channels are then closed.

## Backpressure Policy

1. Event and metrics channels are bounded.
2. If the event channel is full, the hub records a drop.
3. `OverflowPolicyResetStream` forces a dropped data event to reset the active
   stream so blocked readers fail fast.
4. `OverflowPolicyDrop` records the drop and keeps the active stream open.
5. Metrics drops are counted and logged, but they do not reset streams.
