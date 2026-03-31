# Relay Node

The relay package implements the functionality for a libp2p node to act as a relay in the Lib-Mix network.

## Functionality

- **Packet Forwarding**: Receives encrypted shards, strips one layer of encryption, and forwards them to the next hop.
- **Resource Management**: Limits the number of active circuits and bandwidth used by the relay to prevent exhaustion.
- **Zero Knowledge**: Relays do not know the Origin (except for the entry relay) or the Destination (except for the exit relay). They never see the unencrypted content.

## Header-only forwarding model

The relay has two forwarding behaviors depending on the configured encryption
mode:

- **Full onion**: the relay decrypts one hop layer for the full framed payload,
  learns the next hop, and forwards the resulting inner frame.
- **Header-only**: the relay decrypts only the onion header that contains the
  next-hop routing information, rewrites only that header portion, and streams
  the remaining payload bytes onward.

In header-only mode the relay does not allocate and rebuild a second full copy
of the shard payload at each hop. The only place that buffers and reconstructs
the full session payload is the destination-side handler.

## Session-routing forwarding model

When `EnableSessionRouting` is enabled, relays also support an opt-in routed
session cache:

- the first setup frame on a `(baseSessionID, circuit)` decrypts routing state
  once and installs a cache entry
- later session-data frames on that same base session are forwarded using the
  cached next-hop or final-hop delivery state
- idle entries are cleared after `SessionRouteIdleTimeout`, and stream close
  can clear them eagerly

The cache is scoped to the relay's inbound authenticated libp2p stream from the
previous hop. That prevents unrelated peers from sharing routed-session state.
It does not yet add a relay-side MAC for routed data frames, so a malicious
adjacent upstream relay can still cause forwarding attempts until the
destination rejects tampered data.

## Operating a Relay

To operate a relay, a node simply needs to register the Lib-Mix protocol handler and advertise its capability in the DHT.

```go
// Example (Internal)
handler := relay.NewHandler(host, maxCircuits, bufferSize)
host.SetStreamHandler(mixnet.ProtocolID, handler.HandleStream)
```
