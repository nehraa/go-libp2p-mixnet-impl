# Mixnet test tooling

`mixnet/tests/` holds helper tooling around the Go test suites in the
`mixnet/core` package.

## Contents

- `run-tests-dashboard.py`: terminal dashboard that runs
  `TestProductionSanity` either locally or through Docker and renders progress.
- `docker/`: compose files, Dockerfiles, and the containerized sanity-test
  harness.

## Common entry points

Run the main local sanity suite from the repository root:

```bash
go test ./mixnet/core -count=1 -v -run '^TestProductionSanity$'
```

Launch the dashboard wrapper:

```bash
python3 mixnet/tests/run-tests-dashboard.py local
```

Run the containerized sanity suite:

```bash
bash mixnet/tests/docker/run-docker-tests.sh
```

## Environment notes

- The local `TestProductionSanity` flow and the larger in-process stream tests
  create loopback listeners. In restricted sandboxes, `127.0.0.1` binds may be
  denied even when the code is healthy.
- The Docker harness requires a running Docker daemon that can answer
  `docker compose` commands.

Python bytecode under `tests/__pycache__/` is generated locally and is not
tracked.
