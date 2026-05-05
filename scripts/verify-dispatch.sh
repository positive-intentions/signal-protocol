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
#
# For Aeneas verification: charon + aeneas + nightly Rust 2026-02-07.
# If charon or aeneas is missing, aeneas verification is skipped on host
# and must be run via Docker (VERIFY_MODE=aeneas-docker).

set -euo pipefail

export PATH="${HOME}/.opam/5.1.1/bin:${HOME}/cargo/bin:${HOME}/.elan/bin:${PATH}"

mode="${VERIFY_MODE:-auto}"

has_host_toolchain() {
  command -v fstar.exe >/dev/null 2>&1 \
    && command -v cargo-hax >/dev/null 2>&1 \
    && command -v elan >/dev/null 2>&1
}

has_aeneas_host_toolchain() {
  command -v charon >/dev/null 2>&1 \
    && command -v aeneas >/dev/null 2>&1
}

case "${mode}" in
  host)
    exec npm run verify:host
    ;;
  aeneas-host)
    exec npm run verify:aeneas:host
    ;;
  docker)
    exec npm run verify:docker
    ;;
  aeneas-docker)
    exec npm run verify:aeneas:docker
    ;;
  auto)
    if has_host_toolchain; then
      echo "Host verification toolchain detected; running hax verifications in-process."
      if has_aeneas_host_toolchain; then
        echo "Aeneas toolchain detected; running aeneas verifications in-process."
        exec npm run verify:host && npm run verify:aeneas:host
      else
        echo "Aeneas toolchain not found (missing one of: charon, aeneas). Skipping aeneas host verification."
        echo "Run VERIFY_MODE=aeneas-docker for aeneas Docker verification."
        exec npm run verify:host
      fi
    else
      echo "Host verification toolchain not found (missing one of: fstar.exe, cargo-hax, elan)."
      echo "Falling back to Docker. Override with VERIFY_MODE=host to force host mode."
      exec npm run verify:docker
    fi
    ;;
  *)
    echo "Unknown VERIFY_MODE='${mode}'. Use 'host', 'aeneas-host', 'docker', 'aeneas-docker', or 'auto'." >&2
    exit 2
    ;;
esac
