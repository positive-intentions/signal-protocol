# Makefile for Lean extraction of signal-protocol-core
#
# *** EXPERIMENTAL - NOT PART OF THE VERIFIED CLAIM ***
#
# The hax Lean backend is not currently mature enough to verify the
# Double Ratchet module without per-extraction patching of the
# generated `signal_protocol_core.lean`. The previous version of this
# Makefile carried a chain of sed/perl rewrites and a separate
# `patch_fold.pl` script, all of which broke whenever hax bumped a
# minor version.
#
# What is supported here today:
#   - `make extract`   : run hax to (re-)generate signal_protocol_core.lean
#   - `lake build extraction.AbstractCrypto` from the parent directory
#     to verify the hand-written `AbstractCrypto.lean` alone
#
# What is NOT supported:
#   - `make verify` of the extracted modules (needs patches that change
#     between hax versions)
#
# The canonical, CI-gated proof lives in the F* track in
# `signal-protocol-core/proofs/fstar/`. See `proofs/README.md`.

SHELL ?= /usr/bin/env bash

.PHONY: extract clean help

HAX_CLI = cargo-hax -C --no-default-features \; into lean

extract:
	$(HAX_CLI)

clean:
	rm -f Signal_protocol_core*.lean signal_protocol_core.lean
	cd .. && rm -rf .lake lake-manifest.json

help:
	@echo "Experimental Lean verification (not part of the verified claim)."
	@echo "Targets:"
	@echo "  extract  - run hax to extract Lean from Rust"
	@echo "  clean    - remove generated files"
	@echo
	@echo "The maintained proof lives in proofs/fstar/. See proofs/README.md."
