#!/usr/bin/env bash
# Run formal verification in the verify-runner Docker service.
# Tries unprivileged docker first (user in the `docker` group), then
# passwordless sudo (`sudo -n`) for CI or local setups that use rootless Docker.
set -euo pipefail
cd "$(dirname "$0")/.."
if docker compose run --rm verify-runner; then
  exit 0
fi
echo "Retrying verify-runner with sudo -n..." >&2
exec sudo -n docker compose run --rm verify-runner
