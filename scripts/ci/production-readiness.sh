#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

GO_BIN_DIR="${GOBIN:-$(go env GOPATH)/bin}"
export PATH="$GO_BIN_DIR:$PATH"

install_go_tool() {
  local binary="$1"
  local package="$2"

  if command -v "$binary" >/dev/null 2>&1; then
    return
  fi

  go install "$package"
}

run_hub() {
  go vet ./p2p/hub/...
  go test -shuffle=on -count=10 ./p2p/hub/...
  go test -race ./p2p/hub/...
  go test -count=1 -coverprofile=/tmp/hub-cover.out ./p2p/hub/...
  go test -run '^$' -bench '^BenchmarkHub' ./p2p/hub/... -benchtime=1x
  local total
  total="$(go tool cover -func=/tmp/hub-cover.out | awk '/^total:/ {gsub("%", "", $3); print $3}')"
  awk -v total="$total" 'BEGIN { if (total+0 < 85.0) { exit 1 } }'
}

run_repo() {
  go vet ./...
  go test -count=1 ./...
}

run_deadcode() {
  install_go_tool staticcheck honnef.co/go/tools/cmd/staticcheck@latest
  staticcheck ./...
}

run_security() {
  install_go_tool govulncheck golang.org/x/vuln/cmd/govulncheck@latest
  govulncheck ./...
}

run_race() {
  go test -race ./p2p/hub ./p2p/net/mock ./p2p/net/upgrader ./p2p/transport/webtransport ./mixnet/core
}

run_bench() {
  ./mixnet/benchmarks/run_local_benchmarks.sh smoke --runs 1
}

run_docker() {
  go test -count=1 -tags docker_integration ./mixnet/core -run '^(TestDockerComposeUpDown|TestDockerFailureAndRecoverFromFailure)$' -v
}

usage() {
  cat <<'EOF'
Usage: scripts/ci/production-readiness.sh [target...]

Targets:
  hub
  repo
  deadcode
  security
  race
  bench
  docker

If no target is provided, the script runs all targets in the order above.
EOF
}

main() {
  local targets=("$@")
  if [[ ${#targets[@]} -eq 0 ]]; then
    targets=(hub repo deadcode security race bench docker)
  fi

  local target
  for target in "${targets[@]}"; do
    case "$target" in
      hub) run_hub ;;
      repo) run_repo ;;
      deadcode) run_deadcode ;;
      security) run_security ;;
      race) run_race ;;
      bench) run_bench ;;
      docker) run_docker ;;
      -h|--help) usage; exit 0 ;;
      *)
        echo "unknown target: $target" >&2
        usage >&2
        exit 1
        ;;
    esac
  done
}

main "$@"
