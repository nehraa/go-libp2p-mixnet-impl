#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MIXNET_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPO_ROOT="$(cd "$MIXNET_ROOT/.." && pwd)"
cd "$REPO_ROOT"

COMPOSE_FILE="mixnet/tests/docker/docker-compose.test.yml"
TARGET_TEST="${TARGET_TEST:-TestProductionSanity}"
GO_BIN="/usr/local/go/bin/go"
VERBOSE_RUNTIME_LOGS="${MIXNET_SANITY_VERBOSE_LOGS:-0}"

cleanup() {
  docker compose -f "$COMPOSE_FILE" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "=== Building Docker containers ==="
docker compose -f "$COMPOSE_FILE" build

echo "=== Starting mixnet network ==="
docker compose -f "$COMPOSE_FILE" up -d

echo "=== Waiting for containers to be ready ==="
sleep 10

echo "=== Checking container status ==="
docker compose -f "$COMPOSE_FILE" ps

echo "=== Running tests in container (pattern: $TARGET_TEST) ==="
docker compose -f "$COMPOSE_FILE" exec -T mixnet-origin sh -lc \
  "cd /app/mixnet/core && MIXNET_DOCKER_TEST=1 MIXNET_SANITY_VERBOSE_LOGS=$VERBOSE_RUNTIME_LOGS $GO_BIN test . -count=1 -v -run '$TARGET_TEST'"

echo "=== Cleaning up ==="
docker compose -f "$COMPOSE_FILE" down

echo "=== Done ==="
