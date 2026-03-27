# Mixnet local benchmark runner

This benchmark suite runs entirely on local libp2p hosts. It does not use Docker.

## What it measures

- Direct libp2p baseline over Noise.
- Header-only onion and full onion transport latency.
- Legacy versus session-routed mixnet wire behavior.
- CES pipeline cost by data size.
- Hop-count sweep.
- Parallel-circuit sweep.
- Hop x circuit efficiency search.
- Erasure-threshold sweep.
- Header padding, payload padding, jitter, and auth-tag overhead.
- Compression mode comparisons.
- Relay selection mode comparisons.
- Key-exchange cost as a separate timing column in the summary output.

## Header-only benchmark interpretation

The benchmarked header-only path reflects the current relay implementation:

- relays decrypt only the onion header needed for routing
- relays stream payload bytes onward instead of rebuilding a fresh full payload
  copy at every hop
- the destination still buffers/reassembles the final session payload before it
  is delivered to the benchmark reader

That means the header-only numbers include end-to-end session crypto and
destination reconstruction, but they no longer include repeated relay-side
payload-copy overhead that existed in the older buffered forwarding path.

## Quick profile matrix

The quick profile is now a single routed-stream comparison for
`2 hops / 1 circuit` with fixed `256KB` application writes.

It compares:

- direct libp2p baseline
- header-only mixnet with `EnableSessionRouting=true`
- full onion mixnet on the legacy per-frame path

The default quick sizes are:

- `16MB,32MB,64MB,128MB,256MB,512MB,1GB`

The report focuses on:

- one latency graph
- one throughput graph
- one latency table with exact mean ms plus percent overhead
- one throughput table with exact MiB/s plus throughput delta vs direct
- audio preset latency and throughput tables
- video preset latency and throughput tables

Session-routing is benchmarked only for header-only in quick. Full onion stays
on the legacy per-hop decrypt path so the comparison reflects the intended
behavior difference.

Quick also includes media-style stream presets. These do not pace traffic in
real time; instead they shape each run using a bitrate-derived write size and a
fixed virtual stream payload:

| Kind | Quality | Bitrate | Segment | Duration | Derived payload |
| --- | --- | --- | --- | --- | --- |
| audio | low | 96 kbps | 1000 ms | 30 s | about 352 KB |
| audio | medium | 192 kbps | 1000 ms | 30 s | about 703 KB |
| audio | high | 320 kbps | 1000 ms | 30 s | about 1.14 MB |
| video | 480p | 1500 kbps | 1000 ms | 60 s | about 10.7 MB |
| video | 720p | 4000 kbps | 1000 ms | 60 s | about 28.6 MB |
| video | 1080p | 8000 kbps | 1000 ms | 60 s | about 57.2 MB |

If you enable the optional visual proof output, the runner performs a separate
64KB live proof capture after the timed quick scenarios finish for:

- header-only mixnet with `EnableSessionRouting=true`
- full onion mixnet on the legacy path

This proof run is not included in the benchmark timings. It exists only to
record what each hop, the destination network handler, and the destination
application actually observed in one real run. The output is written as
separate files:

- `visual_proof.txt`
- `visual_proof.json`
- matching proof tables inside `report.html`

Enable that extra step with:

```bash
go run ./mixnet/benchmarks/cmd/mixnet-bench --profile quick --visual-proof
```

## Raw data and outlier rule

Each scenario and data size is run multiple times.

- Quick profile: 12 runs.
- Full profile: 6 runs.
- Smoke profile: 3 runs.
- Raw files keep every run.
- The aggregator trims the runs farthest from the median total latency before
  computing the summary. With the current defaults that means:
  - quick keeps 10 of 12 runs
  - full keeps 5 of 6 runs
  - smoke keeps 2 of 3 runs
- Means and sample standard deviations are computed from the remaining runs.

## Default size sweep

The `full` profile uses:

- `1KB,4KB,16KB,64KB,256KB,1MB,4MB,16MB,32MB,50MB`

## Run it

Full sweep:

```bash
./mixnet/run_local_benchmarks.sh
```

Quick focused sweep:

```bash
./mixnet/run_local_benchmarks.sh quick --timeout 10m
```

Targeted run:

```bash
./mixnet/run_local_benchmarks.sh \
  --groups mode-overview,ces-pipeline \
  --sizes 1KB,64KB,1MB \
  --runs 6
```

## Output

Every run writes a timestamped directory under `mixnet/benchmarks/output/` with:

- `raw_runs.csv`
- `raw_runs.jsonl`
- `summary.csv`
- `summary.json`
- `best_hops_circuits.csv`
- `best_hops_circuits.json`
- `metadata.json`
- `report.html`
- `graphs/*.svg`

When `--visual-proof` is enabled, the run also writes:

- `visual_proof.txt`
- `visual_proof.json`

`report.html` links the generated graphs and summarizes the best hop x circuit combinations per size.
For the quick profile it includes the routed comparison charts and the compact
latency/throughput tables described above.

Those timestamped output directories are local-only artifacts and are not kept
in git. See `mixnet/benchmarks/output/README.md` for the expected contents of
that scratch area and use `MIXNET_BENCH_OUTPUT_DIR` if you want the runner to
write elsewhere.

## Notes

- The payload generator uses deterministic random bytes so compression numbers reflect a noise-like payload, not highly compressible text.
- CES reconstruction measurements use only the Reed-Solomon threshold subset, not all shards, so the reported pipeline timings reflect early reconstruction behavior.
