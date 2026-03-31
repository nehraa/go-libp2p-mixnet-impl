#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MIXNET_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$MIXNET_ROOT/.." && pwd)"
cd "$REPO_ROOT"

PROFILE_ARG=""
if [[ $# -gt 0 ]]; then
  case "$1" in
    smoke|quick|full)
      PROFILE_ARG="$1"
      shift
      ;;
  esac
fi

PROFILE="${PROFILE_ARG:-${MIXNET_BENCH_PROFILE:-full}}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
OUTPUT_DIR="${MIXNET_BENCH_OUTPUT_DIR:-mixnet/benchmarks/output/${TIMESTAMP}}"
if [[ "$PROFILE" == "quick" ]]; then
  DEFAULT_MAX_ENCRYPTED_PAYLOAD="2147483648"
else
  DEFAULT_MAX_ENCRYPTED_PAYLOAD="134217728"
fi
MAX_ENCRYPTED_PAYLOAD="${MIXNET_MAX_ENCRYPTED_PAYLOAD:-$DEFAULT_MAX_ENCRYPTED_PAYLOAD}"
GOCACHE_DIR="${GOCACHE:-/tmp/mixnet-go-build-cache}"

if [[ -n "${MIXNET_STREAM_TIMEOUT:-}" ]]; then
  export MIXNET_STREAM_TIMEOUT
fi
export MIXNET_MAX_ENCRYPTED_PAYLOAD="$MAX_ENCRYPTED_PAYLOAD"
export GOCACHE="$GOCACHE_DIR"

mkdir -p "$GOCACHE_DIR"

exec go run ./mixnet/benchmarks/cmd/mixnet-bench \
  --profile "$PROFILE" \
  --output-dir "$OUTPUT_DIR" \
  "$@"
