#!/usr/bin/env bash
# Dispatches `npm run verify` to either the host toolchain or a Docker
# container, depending on whether the required binaries are on $PATH.
#
# Override with VERIFY_MODE=host or VERIFY_MODE=docker.
#
# Host toolchain requires: opam + OCaml 5.1.1, F* (fstar.exe), Z3 4.13.3,
# Rocq + coq-record-update, Lean 4 via elan, nightly Rust 2025-02-01, and
# hax (cargo-hax + hax-engine). If any of fstar.exe / cargo-hax / elan is
# missing we fall back to the Docker image built from the `verification`
# target in the Dockerfile.

set -euo pipefail

export PATH="${HOME}/.opam/5.1.1/bin:${HOME}/.cargo/bin:${HOME}/.elan/bin:${PATH}"

mode="${VERIFY_MODE:-auto}"

has_host_toolchain() {
  command -v fstar.exe >/dev/null 2>&1 \
    && command -v cargo-hax >/dev/null 2>&1 \
    && command -v elan >/dev/null 2>&1
}

case "${mode}" in
  host)
    exec npm run verify:host
    ;;
  docker)
    exec npm run verify:docker
    ;;
  auto)
    if has_host_toolchain; then
      echo "Host verification toolchain detected; running in-process."
      exec npm run verify:host
    else
      echo "Host verification toolchain not found (missing one of: fstar.exe, cargo-hax, elan)."
      echo "Falling back to Docker. Override with VERIFY_MODE=host to force host mode."
      exec npm run verify:docker
    fi
    ;;
  *)
    echo "Unknown VERIFY_MODE='${mode}'. Use 'host', 'docker', or 'auto'." >&2
    exit 2
    ;;
esac
