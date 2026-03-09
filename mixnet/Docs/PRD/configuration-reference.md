# Configuration Reference (Implementation)

This document provides a complete reference for all configuration options in the Go implementation, including those not present in the original design.

## Why these configuration choices exist

The `MixnetConfig` surface is intentionally split into a small set of knobs that
control four different concerns:

1. **Path privacy**: how many relays are used and how relays are selected.
2. **Reliability**: how many circuits exist in parallel and how many shards are
   required for reconstruction.
3. **Performance**: whether to compress, how much work is done per hop, and how
   much redundancy is introduced.
4. **Traffic-analysis resistance**: whether to add padding, timing jitter, and
   authenticity metadata.

The available flags exist so operators can tune those trade-offs explicitly
instead of being forced into a single privacy/performance profile.

## Flags, purpose, and benefit at a glance

### Routing and path construction flags

| Flag | Choices / Values | Purpose | Main Benefit | Why the default was chosen |
| --- | --- | --- | --- | --- |
| `HopCount` | `1-10` | Controls how many relays a shard traverses. | More hops increase unlinkability between sender and receiver. | `2` is a middle ground that adds meaningful relay indirection without making setup and latency too expensive for common applications. |
| `CircuitCount` | `1-20` | Controls how many parallel circuits are established. | More circuits improve throughput and resilience because traffic can be distributed across multiple paths. | `3` gives redundancy and parallelism without the overhead of maintaining a large circuit set by default. |
| `SelectionMode` | `rtt`, `random`, `hybrid` | Chooses how candidate relays are ranked and selected. | Lets deployments favor speed, privacy randomness, or a balance of both. | `rtt` is the least surprising default for general-purpose use because it keeps latency lower while still using multiple relays. |
| `SamplingSize` | positive integer, or `0` for auto | Determines how many relay candidates discovery evaluates before selection. | Larger samples give the selector more room to find good and diverse relays. | `0` defers to an implementation-derived value (`3 * HopCount * CircuitCount`) so users get a usable sample size without hand-tuning. |
| `RandomnessFactor` | `0.0-1.0` | Weighs randomness in hybrid relay selection. | Allows privacy/performance balancing without abandoning latency awareness entirely. | `0.3` biases toward useful RTT performance while still injecting non-determinism into path choice. |

### Payload processing flags

| Flag | Choices / Values | Purpose | Main Benefit | Why the default was chosen |
| --- | --- | --- | --- | --- |
| `Compression` | `gzip`, `snappy` | Compresses data before encryption/sharding when CES is enabled. | Compression reduces bytes sent and can lower shard count for compressible data. | `gzip` was chosen as the default because it prioritizes better size reduction out of the box. |
| `UseCESPipeline` | `true`, `false` | Enables or bypasses the Compress-Encrypt-Shard pipeline. | CES improves redundancy and makes multi-path delivery more effective. | `true` keeps the default behavior aligned with the full Lib-Mix design rather than the reduced fast path. |
| `ErasureThreshold` | `1..CircuitCount`, or `0` for auto | Controls how many shards must arrive before reconstruction can succeed. | Lower thresholds tolerate loss; higher thresholds reduce reconstruction ambiguity and overhead. | `0` lets the implementation derive `ceil(CircuitCount * 0.6)`, which is a balanced recovery threshold for most deployments. |
| `EncryptionMode` | `full`, `header-only` | Chooses whether each hop decrypts only routing headers or the entire payload layer. | Gives operators a way to reduce per-hop CPU cost for large payloads. | `full` is the default because it favors stronger layered protection over throughput optimizations. |

### Traffic-analysis resistance flags

| Flag | Choices / Values | Purpose | Main Benefit | Why the default was chosen |
| --- | --- | --- | --- | --- |
| `HeaderPaddingEnabled` | `true`, `false` | Enables randomized padding in privacy headers. | Makes hop structure and packet-class fingerprinting harder. | `true` protects metadata by default, since header size is a direct privacy signal. |
| `HeaderPaddingMin` / `HeaderPaddingMax` | byte range | Define the random header padding interval. | Adds variability without requiring every packet to grow to the same size. | `16-256` gives visible size blur with limited overhead. |
| `PayloadPaddingStrategy` | `none`, `random`, `buckets` | Chooses how payload lengths are padded before transmission. | Reduces size-based correlation attacks on encrypted traffic. | `none` keeps the default bandwidth-efficient while still allowing higher-privacy deployments to opt in. |
| `PayloadPaddingMin` / `PayloadPaddingMax` | byte range | Configure random padding when `PayloadPaddingStrategy=random`. | Lets deployments tune how much overhead they are willing to spend to hide size. | `0/0` disables extra overhead until random padding is explicitly requested. |
| `PayloadPaddingBuckets` | ordered slice of sizes | Configure target bucket sizes when `PayloadPaddingStrategy=buckets`. | Makes messages collapse into a few common sizes instead of many unique ones. | `nil` avoids imposing assumptions about message distributions on every application. |
| `EnableAuthTag` | `true`, `false` | Adds per-shard authenticity tags. | Detects corruption or tampering earlier in the pipeline. | `false` avoids extra bytes and HMAC work unless the deployment specifically wants that protection. |
| `AuthTagSize` | `1-32` bytes when enabled | Defines the size of the truncated authenticity tag. | Larger tags make forgery harder. | `16` gives a practical security/performance balance when tags are enabled. |
| `MaxJitter` | milliseconds, `0+` | Adds random delay between shard sends. | Makes timing correlation between shards more difficult. | `50` adds timing noise by default without making interactive workloads unusably slow. |

## Choice-specific guidance

### Relay selection choices

| Choice | Why it exists | When to choose it | Main benefit | Main trade-off |
| --- | --- | --- | --- | --- |
| `SelectionModeRTT` | Some deployments need the best-performing relay path more than maximum unpredictability. | Interactive traffic, demos, latency-sensitive apps. | Lowest average latency among the provided modes. | Path selection is more predictable. |
| `SelectionModeRandom` | Some deployments want path unpredictability even if performance varies widely. | Strong-anonymity scenarios where relay choice diversity matters most. | Highest path randomness. | Performance can be much more variable. |
| `SelectionModeHybrid` | Pure RTT and pure randomness are both extremes. | Balanced deployments that need some unpredictability without giving up performance entirely. | Tunable middle ground through `RandomnessFactor`. | Requires one more parameter to understand and tune. |

### Encryption mode choices

| Choice | Why it exists | When to choose it | Main benefit | Main trade-off |
| --- | --- | --- | --- | --- |
| `EncryptionModeFull` | Preserves the strongest layered-per-hop protection model. | Default deployments and security-first configurations. | Better defense-in-depth across the whole packet. | More CPU work per hop. |
| `EncryptionModeHeaderOnly` | Large payloads can make full per-hop encryption expensive. | High-throughput or CPU-constrained environments. | Lower per-hop processing cost. | Less layered protection on payload bytes. |

### Payload padding choices

| Choice | Why it exists | When to choose it | Main benefit | Main trade-off |
| --- | --- | --- | --- | --- |
| `PaddingStrategyNone` | Some applications cannot afford additional bandwidth overhead. | Default and bandwidth-sensitive deployments. | Best efficiency and lowest latency overhead. | Message sizes remain more distinguishable. |
| `PaddingStrategyRandom` | Randomized padding makes size correlation harder on a per-message basis. | High-privacy deployments with variable message sizes. | Better size obfuscation without fixed buckets. | Can be wasteful if ranges are large. |
| `PaddingStrategyBuckets` | Many apps send messages in recurring size classes. | Apps with known traffic patterns such as chat, RPC, or file chunking. | Efficient obfuscation by rounding up to common sizes. | Requires thoughtful bucket design. |

## Core Configuration (From Original Design)

### `HopCount`
- **Type**: `int`
- **Range**: 1-10
- **Default**: 2
- **Description**: Number of relay nodes in each circuit
- **Privacy Impact**: Higher = more privacy, higher latency
- **Requirement**: Req 1

### `CircuitCount`
- **Type**: `int`
- **Range**: 1-20
- **Default**: 3
- **Description**: Number of parallel circuits to establish
- **Privacy Impact**: Higher = more redundancy, more bandwidth
- **Requirement**: Req 2

### `Compression`
- **Type**: `string`
- **Values**: `"gzip"`, `"snappy"`
- **Default**: `"gzip"`
- **Description**: Compression algorithm for CES pipeline
- **Performance Impact**: Gzip = better compression, Snappy = lower latency
- **Requirement**: Req 3

### `ErasureThreshold`
- **Type**: `int`
- **Range**: 1 to `CircuitCount`
- **Default**: `ceil(CircuitCount * 0.6)`
- **Description**: Minimum shards needed to reconstruct data
- **Reliability Impact**: Lower = faster reconstruction, less redundancy
- **Requirement**: Req 3

### `SelectionMode`
- **Type**: `SelectionMode` (enum)
- **Values**: `"rtt"`, `"random"`, `"hybrid"`
- **Default**: `"rtt"`
- **Description**: Relay selection strategy
- **Privacy Impact**: 
  - `rtt`: Best performance, predictable (lower privacy)
  - `random`: Unpredictable (higher privacy), variable performance
  - `hybrid`: Balanced
- **Requirement**: Req 4, Req 5

### `SamplingSize`
- **Type**: `int`
- **Default**: `3 * (HopCount * CircuitCount)`
- **Description**: Number of relay candidates to sample in hybrid mode
- **Performance Impact**: Higher = more DHT queries, better relay quality
- **Requirement**: Req 4

### `RandomnessFactor`
- **Type**: `float64`
- **Range**: 0.0-1.0
- **Default**: 0.3
- **Description**: Weight of randomness vs RTT in hybrid selection
- **Privacy Impact**: Higher = more random (higher privacy), variable performance
- **Requirement**: Req 5

---

## Implementation-Specific Configuration

### `UseCESPipeline`
- **Type**: `bool`
- **Default**: `true`
- **Description**: Enable/disable Compress-Encrypt-Shard pipeline
- **When to Disable**: 
  - Small messages (<1KB)
  - Latency-critical applications
  - Don't need redundancy
- **Impact When Disabled**:
  - ✅ Lower latency
  - ✅ Lower CPU usage
  - ❌ No compression
  - ❌ No redundancy (all circuits must succeed)
- **Requirement**: Req 21

### `EncryptionMode`
- **Type**: `EncryptionMode` (enum)
- **Values**: `"full"`, `"header-only"`
- **Default**: `"full"`
- **Description**: Encryption strategy
- **When to Use Header-Only**:
  - Large payloads (>16KB)
  - CPU-constrained relays
  - Acceptable to encrypt payload once end-to-end
- **Performance Impact**: Header-only is 2-5× faster for large payloads
- **Requirement**: Req 3A

---

## Padding Configuration

### `HeaderPaddingEnabled`
- **Type**: `bool`
- **Default**: `true`
- **Description**: Enable random padding in privacy headers
- **When to Disable**: Only in bandwidth-constrained or low-privacy deployments
- **Privacy Impact**: When enabled, prevents relay fingerprinting by header size
- **Bandwidth Impact**: +0-256 bytes per shard
- **Requirement**: Req 22

### `HeaderPaddingMin`
- **Type**: `int`
- **Default**: 16
- **Description**: Minimum header padding in bytes
- **Recommendation**: Set to 0 for efficiency

### `HeaderPaddingMax`
- **Type**: `int`
- **Default**: 256
- **Description**: Maximum header padding in bytes
- **Recommendation**: 256 bytes is sufficient for most use cases

### `PayloadPaddingStrategy`
- **Type**: `PaddingStrategy` (enum)
- **Values**: `"none"`, `"random"`, `"buckets"`
- **Default**: `"none"`
- **Description**: Payload length padding strategy
- **When to Use**:
  - `none`: Low-privacy deployments, bandwidth-constrained
  - `random`: High-privacy, variable message sizes
  - `buckets`: High-privacy, common message sizes
- **Requirement**: Req 23

### `PayloadPaddingMin`
- **Type**: `int`
- **Default**: 0
- **Description**: Minimum random padding in bytes (for `random` strategy)
- **Recommendation**: Set to 10-20% of average message size

### `PayloadPaddingMax`
- **Type**: `int`
- **Default**: 0
- **Description**: Maximum random padding in bytes (for `random` strategy)
- **Recommendation**: Set to 50-100% of average message size

### `PayloadPaddingBuckets`
- **Type**: `[]int`
- **Default**: unset (`nil`)
- **Description**: Target sizes for bucket padding
- **Recommendation**: Choose buckets based on your message size distribution
- **Example**: For chat app: `[256, 1024, 4096]` (short, medium, long messages)

---

## Integrity Configuration

### `EnableAuthTag`
- **Type**: `bool`
- **Default**: `false`
- **Description**: Enable per-shard authenticity tags
- **When to Enable**:
  - Untrusted relay networks
  - Need early corruption detection
  - Debugging integrity issues
- **Performance Impact**: +16 bytes per shard, +HMAC computation
- **Requirement**: Req 24

### `AuthTagSize`
- **Type**: `int`
- **Default**: 16
- **Description**: Size of truncated HMAC tag in bytes
- **Recommendation**: 16 bytes (128 bits) is sufficient
- **Security**: Don't go below 12 bytes (96 bits)

---

## Timing Configuration

### `MaxJitter`
- **Type**: `int` (milliseconds)
- **Default**: 50
- **Description**: Maximum random delay between shard transmissions
- **When to Enable**: High-privacy deployments
- **Privacy Impact**: Breaks timing correlations between shards
- **Latency Impact**: Adds 0-`MaxJitter` ms per shard
- **Recommendation**: 
  - Low-latency apps: 0-10ms
  - Balanced: 10-50ms
  - High-privacy: 50-200ms
- **Requirement**: Req 25

---

## Relay Configuration

### `MaxCircuits`
- **Type**: `int`
- **Default**: 100
- **Description**: Maximum concurrent circuits for relay nodes
- **When to Adjust**:
  - Increase for high-capacity relays
  - Decrease for resource-constrained nodes
- **Requirement**: Req 20, Req 26

### `MaxBandwidth`
- **Type**: `int64` (bytes/sec)
- **Default**: 10485760 (10 MB/s)
- **Description**: Maximum bandwidth per circuit
- **When to Adjust**:
  - Increase for high-bandwidth relays
  - Decrease to prevent abuse
- **Requirement**: Req 20, Req 26

---

## Timeout Configuration

### `ConstructionTimeout`
- **Type**: `time.Duration`
- **Default**: 30 seconds
- **Description**: Maximum time to establish all circuits
- **When to Adjust**:
  - Increase for slow networks
  - Decrease for fast networks

### `HealthCheckInterval`
- **Type**: `time.Duration`
- **Default**: 10 seconds
- **Description**: Interval between circuit health checks
- **When to Adjust**:
  - Decrease for faster failure detection
  - Increase to reduce overhead

### `ShardReceptionTimeout`
- **Type**: `time.Duration`
- **Default**: 30 seconds
- **Description**: Maximum time to wait for shard reconstruction
- **When to Adjust**:
  - Increase for slow networks
  - Decrease for fast networks

### `GracefulShutdownTimeout`
- **Type**: `time.Duration`
- **Default**: 10 seconds
- **Description**: Maximum time to wait for close acknowledgments
- **When to Adjust**:
  - Increase for slow networks
  - Decrease for fast shutdown

---

## Configuration Presets

### Low-Latency Preset
```go
config := &MixnetConfig{
    HopCount:               1,
    CircuitCount:           2,
    Compression:            "gzip",
    ErasureThreshold:       1,
    UseCESPipeline:         false,
    EncryptionMode:         "header-only",
    SelectionMode:          "rtt",
    PayloadPaddingStrategy: "none",
    MaxJitter:              0,
}
```
**Use Case**: Real-time chat, gaming, VoIP

### Balanced Preset (Default)
```go
config := &MixnetConfig{
    HopCount:               2,
    CircuitCount:           3,
    Compression:            "gzip",
    ErasureThreshold:       2,
    UseCESPipeline:         true,
    EncryptionMode:         "full",
    SelectionMode:          "rtt",
    HeaderPaddingEnabled:   true,
    HeaderPaddingMin:       16,
    HeaderPaddingMax:       256,
    PayloadPaddingStrategy: "none",
    MaxJitter:              50,
}
```
**Use Case**: General-purpose applications

### High-Privacy Preset
```go
config := &MixnetConfig{
    HopCount:               3,
    CircuitCount:           5,
    Compression:            "gzip",
    ErasureThreshold:       3,
    UseCESPipeline:         true,
    EncryptionMode:         "full",
    SelectionMode:          "hybrid",
    RandomnessFactor:       0.5,
    HeaderPaddingEnabled:   true,
    HeaderPaddingMax:       256,
    PayloadPaddingStrategy: "buckets",
    PayloadPaddingBuckets:  []int{1024, 4096, 16384, 65536},
    EnableAuthTag:          true,
    AuthTagSize:            16,
    MaxJitter:              100,
}
```
**Use Case**: Whistleblowing, journalism, activism

### High-Throughput Preset
```go
config := &MixnetConfig{
    HopCount:               2,
    CircuitCount:           5,
    Compression:            "gzip",
    ErasureThreshold:       3,
    UseCESPipeline:         true,
    EncryptionMode:         "header-only",
    SelectionMode:          "rtt",
    PayloadPaddingStrategy: "none",
    MaxJitter:              0,
}
```
**Use Case**: File transfer, video streaming

---

## Configuration Validation Rules

The implementation validates configuration at initialization:

1. **HopCount**: Must be 1-10
2. **CircuitCount**: Must be 1-20
3. **ErasureThreshold**: Must be 1 to `CircuitCount`
4. **RandomnessFactor**: Must be 0.0-1.0
5. **HeaderPaddingMin**: Must be ≤ `HeaderPaddingMax`
6. **PayloadPaddingMin**: Must be ≤ `PayloadPaddingMax`
7. **PayloadPaddingBuckets**: Must be in ascending order
8. **AuthTagSize**: Must be 12-32 bytes
9. **MaxJitter**: Must be ≥ 0

Invalid configurations return an error immediately.

---

## Performance vs Privacy Trade-offs

| Configuration | Latency | Bandwidth | Privacy | Reliability |
|---------------|---------|-----------|---------|-------------|
| Low-Latency | ✅ Best | ✅ Best | ❌ Lowest | ❌ Lowest |
| Balanced | ✅ Good | ✅ Good | ✅ Good | ✅ Good |
| High-Privacy | ❌ Worst | ❌ Worst | ✅ Best | ✅ Best |
| High-Throughput | ✅ Good | ❌ High | ✅ Medium | ✅ Best |

---

## Monitoring Configuration Impact

Use the MetricsCollector to monitor how configuration affects performance:

```go
metrics := mixnet.GetMetrics()
fmt.Printf("Avg Circuit RTT: %v\n", metrics.AvgCircuitRTT)
fmt.Printf("Compression Ratio: %.2f\n", metrics.CompressionRatio)
fmt.Printf("Circuit Success Rate: %.2f%%\n", metrics.ConstructionSuccessRate * 100)
```

Adjust configuration based on metrics:
- High RTT → Reduce `HopCount` or use `SelectionMode: "rtt"`
- Low compression ratio → Disable `UseCESPipeline` for small messages
- High failure rate → Increase `ErasureThreshold` or `CircuitCount`

---

## Configuration Best Practices

1. **Start with defaults**: The balanced preset works for most use cases
2. **Measure first**: Use metrics to identify bottlenecks before tuning
3. **Tune incrementally**: Change one parameter at a time
4. **Test in production**: Synthetic benchmarks don't capture real-world behavior
5. **Document choices**: Record why you chose specific values
6. **Monitor continuously**: Configuration needs change as usage patterns evolve

---

## Future Configuration Options

Potential additions for future versions:

- **Adaptive Configuration**: Automatically adjust based on network conditions
- **Per-Destination Config**: Different settings for different peers
- **Traffic Shaping**: Rate limiting, burst control
- **Advanced Padding**: Cover traffic, dummy messages
- **Circuit Pooling**: Reuse circuits across streams
- **Multi-Path Routing**: Use different paths for different shards

These are not yet implemented but may be added based on user feedback and research.
