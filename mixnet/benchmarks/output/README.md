# Benchmark output

`mixnet/benchmarks/output/` is the default destination for local benchmark
artifacts produced by `./mixnet/run_local_benchmarks.sh` and
`go run ./mixnet/benchmarks/cmd/mixnet-bench`.

These timestamped run directories are intentionally local-only and are ignored
by git. Each run may contain:

- `raw_runs.csv` and `raw_runs.jsonl`
- `summary.csv` and `summary.json`
- `best_hops_circuits.csv` and `best_hops_circuits.json`
- `metadata.json`
- `report.html`
- `graphs/*.svg`
- optional `visual_proof.txt` and `visual_proof.json`

To write somewhere else, set `MIXNET_BENCH_OUTPUT_DIR` before invoking the
runner.
