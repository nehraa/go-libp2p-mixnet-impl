# Design Deviations and Rationale

This document explains aspects of the implementation that differ from the original design document, along with the reasons why these deviations were necessary or beneficial.

## 1. Mixnet Core vs Stream Upgrader Interface

### Original Design
The design specified a `StreamUpgrader` trait/interface that wraps existing libp2p streams:

```rust
trait StreamUpgrader {
    async fn upgrade_outbound(&mut self, destination: PeerId, protocol: ProtocolId) -> Result<MixStream>;
    async fn upgrade_inbound(&mut self, stream: Stream) -> Result<MixStream>;
}
```

### Actual Implementation
The implementation uses a `Mixnet` struct as the central coordinator:

```go
type Mixnet struct {
    config          *MixnetConfig
    host            host.Host
    routing         routing.Routing
    circuitMgr      *circuit.CircuitManager
    pipeline        *ces.CESPipeline
    relayHandler    *relay.Handler
    // ... other fields
}

func (m *Mixnet) Send(ctx context.Context, dest peer.ID, data []byte) error
func (m *Mixnet) SendWithSession(ctx context.Context, dest peer.ID, data []byte, sessionID string) error
func (m *Mixnet) ReceiveHandler() func(network.Stream)
func (m *Mixnet) OpenStream(ctx context.Context, dest peer.ID) (*MixStream, error)
func (m *Mixnet) AcceptStream(ctx context.Context) (*MixStream, error)
```

### Rationale
**Why the deviation:**
1. **Go Idioms**: Go doesn't have traits/interfaces in the Rust sense. The `Mixnet` struct is more idiomatic.
2. **State Management**: The `Mixnet` struct centralizes state (circuits, keys, metrics) rather than spreading it across multiple components.
3. **Lifecycle Management**: A single struct makes initialization and cleanup simpler.
4. **Testing**: Easier to mock and test a single struct than multiple interface implementations.

**Trade-offs:**
- ✅ Simpler API surface
- ✅ Easier state management
- ❌ Less modular (harder to swap implementations)
- ❌ Tighter coupling between components

**Could it have been done as designed?** Yes, but it would have required more boilerplate and interface definitions. The current approach is more pragmatic for Go.

---

## 2. Noise Protocol Implementation

### Original Design
The design specified using the Noise Protocol Framework with XX handshake pattern:

```rust
struct KeyManager {
    fn generate_circuit_keys(&mut self, circuit_id: CircuitId, hop_count: usize) -> Result<Vec<NoiseKeyPair>>;
}
```

### Actual Implementation
The implementation uses Noise XX for key exchange and XChaCha20-Poly1305 for
per-hop CES encryption:

```go
// Key exchange uses Noise XX via the flynn/noise library
var keyExchangeCipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

hs, _ := noise.NewHandshakeState(noise.Config{
    CipherSuite:   keyExchangeCipherSuite,
    Pattern:       noise.HandshakeXX,
    Initiator:     true,
    StaticKeypair: kp,
})

// Per-hop CES encryption uses XChaCha20-Poly1305 directly
cipher, err := chacha20poly1305.NewX(key)
```

### Rationale
**Why the deviation:**
1. **Focused use of Noise**: Noise XX is used for the initial key exchange handshake where its mutual authentication properties are needed, but per-hop layered encryption uses XChaCha20-Poly1305 directly for simplicity and performance.
2. **Performance**: Direct AEAD for per-hop encryption avoids repeated Noise handshake overhead on the data path.
3. **Clarity**: Separating key exchange (Noise XX) from bulk encryption (AEAD) makes the security model easier to audit.

**Trade-offs:**
- ✅ Authenticated key exchange via Noise XX
- ✅ Faster per-hop encryption via direct AEAD
- ✅ Clear separation of concerns
- ❌ Two cryptographic subsystems to understand
- ❌ Manual key lifecycle for hop keys after Noise key exchange

**Could it have been done as designed?** Partially done as designed: Noise XX is used for key exchange. Per-hop encryption uses the same underlying primitive (ChaCha20-Poly1305) but bypasses the Noise transport layer for data, which is a practical trade-off.

---

## 3. Circuit Construction Algorithm

### Original Design
The design specified constructing all circuits in parallel:

```
for circuit_idx in 0..config.circuit_count:
    circuit = establish_circuit(circuit_relays, destination)?
    circuits.push(circuit)
```

### Actual Implementation
The implementation constructs circuits sequentially with error handling:

```go
func (m *CircuitManager) BuildCircuits(ctx context.Context, dest peer.ID, relays []RelayInfo) ([]*Circuit, error) {
    circuits := m.buildUniqueCircuits(filtered)
    
    for i, c := range circuits {
        if err := m.establishCircuit(ctx, c, dest); err != nil {
            // Clean up partial circuits
            m.cleanupCircuits(circuits[:i])
            return nil, err
        }
    }
    return circuits, nil
}
```

### Rationale
**Why the deviation:**
1. **Error Handling**: Sequential construction makes cleanup easier on failure
2. **Resource Management**: Prevents resource exhaustion from parallel connection attempts
3. **Debugging**: Easier to trace which circuit failed
4. **Relay Load**: Avoids overwhelming relays with simultaneous connection requests

**Trade-offs:**
- ✅ Better error handling
- ✅ Easier debugging
- ✅ More predictable resource usage
- ❌ Slower circuit construction (sequential vs parallel)
- ❌ Higher latency to first byte

**Could it have been done as designed?** Yes, parallel construction is possible but requires more complex error handling and cleanup logic. The sequential approach is more robust.

**Future Improvement**: Could add a `max_parallel_circuits` config option to allow limited parallelism (e.g., 3 at a time).

---

## 4. Shard Transmission

### Original Design
The design specified streaming shards without buffering:

```
THE Relay_Node SHALL forward the remaining encrypted payload to the next-hop peer without buffering
```

### Actual Implementation
The implementation uses length-prefixed framing, and the header-only mode now
uses a stream-through relay path:

```go
// Write length prefix
binary.Write(stream, binary.BigEndian, uint32(len(shard)))
// Write shard data
stream.Write(shard)
```

For `header-only` forwarding specifically, the relay:

1. Reads the frame header and encrypted onion header
2. Decrypts only the routing/control header
3. Rewrites only the header portion for the next hop
4. Streams the remaining payload bytes to the outbound stream without
   rebuilding a second full payload buffer

### Rationale
**Why the deviation:**
1. **Framing**: Length prefixes enable proper message boundaries
2. **Multiplexing**: Allows multiple messages on the same stream
3. **Error Recovery**: Receiver knows when a message is incomplete
4. **Compatibility**: Standard practice in network protocols

**Trade-offs:**
- ✅ Proper message framing
- ✅ Better error detection
- ✅ Enables stream reuse
- ✅ Header-only relays no longer make a fresh full payload copy per hop
- ❌ 4 bytes overhead per shard
- ❌ Slight buffering (length prefix must be read first)

**Could it have been done as designed?** No, streaming without framing is impractical. The receiver needs to know message boundaries. The design likely assumed this implicitly.

---

## 5. Erasure Coding Threshold

### Original Design
The design specified a fixed 60% threshold:

```
threshold=ceil(config.circuit_count * 0.6)
```

### Actual Implementation
The implementation allows configurable threshold:

```go
type MixnetConfig struct {
    ErasureThreshold int  // Configurable, defaults to 60%
}
```

### Rationale
**Why the deviation:**
1. **Flexibility**: Different applications have different reliability requirements
2. **Performance**: Lower threshold = faster reconstruction but less redundancy
3. **Bandwidth**: Higher threshold = more redundancy but more bandwidth
4. **Testing**: Easier to test edge cases with configurable threshold

**Trade-offs:**
- ✅ More flexible
- ✅ Easier to tune for specific use cases
- ❌ More configuration complexity
- ❌ Users might choose insecure values

**Could it have been done as designed?** Yes, but fixed 60% is arbitrary. Making it configurable (with sane defaults) is better.

---

## 6. Relay Discovery

### Original Design
The design specified querying DHT for 3× required relays:

```
relay_pool = discover_relays(required_relays * 3, exclude=[origin, destination])
```

### Actual Implementation
The implementation uses configurable sampling:

```go
type MixnetConfig struct {
    SelectionMode    SelectionMode  // rtt | random | hybrid
    SamplingSize     int            // For hybrid mode
    RandomnessFactor float64        // For hybrid mode
}
```

### Rationale
**Why the deviation:**
1. **Privacy**: Pure RTT selection is predictable (attackers can guess relay choices)
2. **Diversity**: Random selection increases path diversity
3. **Hybrid**: Balances performance (RTT) and privacy (randomness)
4. **Research**: Hybrid selection is based on mixnet research (Loopix, Nym)

**Trade-offs:**
- ✅ Better privacy (less predictable)
- ✅ More flexible
- ✅ Research-backed
- ❌ More complex
- ❌ Random selection may have higher latency

**Could it have been done as designed?** Yes, but pure RTT selection is a known privacy weakness. The hybrid approach is a significant improvement.

---

## 7. Key Management

### Original Design
The design specified per-circuit ephemeral keys:

```rust
struct KeyManager {
    active_keys: HashMap<CircuitId, Vec<NoiseKeyPair>>,
}
```

### Actual Implementation
The implementation uses per-session keys:

```go
type Mixnet struct {
    circuitKeys map[string][][]byte  // sessionID -> keys
}

type DestinationHandler struct {
    keys map[string]sessionKey  // sessionID -> keys
}
```

### Rationale
**Why the deviation:**
1. **Concurrent Streams**: Multiple streams can share the same circuits
2. **Session Isolation**: Each stream gets unique keys even if using same circuits
3. **Key Reuse**: Circuits can be reused across sessions (with different keys)
4. **Efficiency**: Avoids rebuilding circuits for each new stream

**Trade-offs:**
- ✅ Supports concurrent streams
- ✅ More efficient (circuit reuse)
- ✅ Better session isolation
- ❌ More complex key management
- ❌ Requires session ID generation

**Could it have been done as designed?** Yes, but per-circuit keys don't support concurrent streams well. Per-session keys are more practical.

---

## 8. Error Handling

### Original Design
The design specified four error categories with specific handling:

```rust
enum LibMixError {
    Config(ConfigError),
    Network(NetworkError),
    Crypto(CryptoError),
    Data(DataError),
}
```

### Actual Implementation
The implementation uses a structured `MixnetError` type with error codes and
factory constructors:

```go
type MixnetError struct {
    Code    string
    Message string
    Cause   error
}

func ErrConfigInvalid(msg string) *MixnetError
func ErrDiscoveryFailed(msg string) *MixnetError
func ErrCircuitFailed(msg string) *MixnetError
func ErrEncryptionFailed(msg string) *MixnetError
func ErrCompressionFailed(msg string) *MixnetError
func ErrShardingFailed(msg string) *MixnetError
func ErrTransportFailed(msg string) *MixnetError
func ErrTimeout(msg string) *MixnetError
func ErrResourceExhausted(msg string) *MixnetError
func ErrProtocolError(msg string) *MixnetError
```

Helper functions `IsRetryable` and `IsFatal` allow callers to classify errors
programmatically.

### Rationale
**Why the deviation:**
1. **Go Idioms**: `MixnetError` implements the `error` interface and supports Go 1.13+ `errors.Is`/`errors.As` via `Unwrap`, keeping Go-idiomatic usage while adding structure.
2. **Error Classification**: Error codes provide the same categorization as the Rust enum but without requiring exhaustive type switches.
3. **Context Propagation**: The `WithCause` method chains underlying errors for debugging without losing the high-level category.
4. **Retry Logic**: `IsRetryable` and `IsFatal` give callers a simple decision path without knowing every error code.

**Trade-offs:**
- ✅ Structured error codes for programmatic handling
- ✅ Idiomatic Go error wrapping
- ✅ Built-in retry/fatal classification
- ✅ Context propagation via `WithCause`
- ❌ More types than plain `fmt.Errorf` wrapping
- ❌ Callers must import the package to use the typed constructors

**Could it have been done as designed?** The Rust-style enum has no direct Go equivalent, but `MixnetError` achieves the same categorization with factory constructors and error codes. The result is closer to the original intent than plain `fmt.Errorf` wrapping.

---

## 9. Metrics Exposure

### Original Design
The design specified a MetricsCollector struct:

```rust
struct ProtocolMetrics {
    avg_circuit_rtt: Duration,
    construction_success_rate: f64,
    // ...
}
```

### Actual Implementation
The implementation uses atomic counters and a MetricsExporter:

```go
type MetricsCollector struct {
    CircuitsEstablished    int64  // atomic
    CircuitsFailed         int64  // atomic
    // ...
}

type MetricsExporter struct {
    collector *MetricsCollector
    // Exports to Prometheus, JSON, etc.
}
```

### Rationale
**Why the deviation:**
1. **Concurrency**: Atomic counters are thread-safe without locks
2. **Performance**: Lock-free metrics don't block data path
3. **Flexibility**: MetricsExporter allows multiple export formats
4. **Integration**: Easier to integrate with monitoring systems (Prometheus, Grafana)

**Trade-offs:**
- ✅ Better performance (lock-free)
- ✅ More flexible (multiple export formats)
- ✅ Production-ready
- ❌ More complex (separate exporter component)

**Could it have been done as designed?** Yes, but the current approach is more production-ready and performant.

---

## 10. Graceful Shutdown

### Original Design
The design specified sending close signals through circuits:

```
WHEN the application closes a stream, THE Lib_Mix_Protocol SHALL send a close signal through all active circuits
```

### Actual Implementation
The implementation uses a message type system:

```go
const (
    msgTypeData     byte = 0x00
    msgTypeCloseReq byte = 0x01
    msgTypeCloseAck byte = 0x02
)
```

### Rationale
**Why the deviation:**
1. **Explicit Signaling**: Message types make close intent explicit
2. **Acknowledgment**: CloseAck enables proper cleanup confirmation
3. **Debugging**: Easier to trace close sequences
4. **Reliability**: Distinguishes close from connection failure

**Trade-offs:**
- ✅ More reliable shutdown
- ✅ Better debugging
- ✅ Explicit acknowledgment
- ❌ More complex protocol
- ❌ Additional message overhead

**Could it have been done as designed?** The design was underspecified. The current approach is more robust.

---

## Summary

| Deviation | Reason | Could Be Done As Designed? |
|-----------|--------|----------------------------|
| Mixnet struct vs StreamUpgrader | Go idioms, simpler state management | Yes, but more boilerplate |
| Noise XX key exchange + direct AEAD | Focused Noise use for auth, direct AEAD for speed | Partially done as designed |
| Sequential circuit construction | Better error handling | Yes, but harder cleanup |
| Length-prefixed framing | Message boundaries required | No, design was underspecified |
| Configurable erasure threshold | Flexibility | Yes, but less flexible |
| Hybrid relay selection | Better privacy | Yes, but weaker privacy |
| Per-session keys | Concurrent streams | Yes, but less efficient |
| Structured MixnetError | Go idioms + error classification | Closer to original intent than plain errors |
| Atomic metrics | Performance | Yes, but slower |
| Message type system | Explicit signaling | Design was underspecified |

**Overall Assessment**: Most deviations are improvements based on:
1. **Language Idioms**: Go-specific patterns (error handling, struct-based design)
2. **Production Requirements**: Metrics, resource management, error handling
3. **Privacy Research**: Hybrid relay selection, padding, jitter
4. **Implementation Experience**: Framing, session management, concurrent streams

The core design principles (onion routing, sharding, erasure coding) remain intact. Deviations are primarily in implementation details and production-readiness features.
