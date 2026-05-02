# Makefile for Rocq extraction of signal-protocol-core
#
# *** EXPERIMENTAL - NOT PART OF THE VERIFIED CLAIM ***
#
# The hax Rocq backend is not currently mature enough to verify the
# Double Ratchet module without significant per-extraction patching.
# The previous version of this Makefile carried ~70 lines of sed/perl
# rewrites of hax output, which were too fragile to maintain.
#
# What is supported here today:
#   - `make extract`        : run hax to (re-)generate Signal_protocol_core_*.v
#   - `make verify-abstract`: verify the hand-written `AbstractCrypto.v`
#                             alone (no hax output, no patching)
#
# What is NOT supported:
#   - Verifying the extracted modules (they need patches that change
#     between hax versions)
#   - `make verify` / `make verify-lite` (left as TODO; PRs welcome)
#
# The canonical, CI-gated proof lives in the F* track in
# `signal-protocol-core/proofs/fstar/`. See `proofs/README.md`.

ROCQ_BIN ?= rocq
SHELL    ?= /usr/bin/env bash

.PHONY: extract verify-abstract clean help

HAX_CLI = cargo-hax -C --no-default-features \; into coq

extract:
	$(HAX_CLI)

verify-abstract:
	@echo "Compiling AbstractCrypto.v..."
	$(ROCQ_BIN) compile -q -w -native-compiler=no -R . Signal_protocol_core AbstractCrypto.v
	@echo "AbstractCrypto.v verified."

clean:
	rm -f Signal_protocol_core*.vo Signal_protocol_core*.glob
	rm -f Signal_protocol_core*.vok Signal_protocol_core*.vos
	rm -f Core_Extra.vo Core_Extra.glob Core_Extra.vok Core_Extra.vos
	rm -f .*.aux *.aux _CoqProject

help:
	@echo "Experimental Rocq verification (not part of the verified claim)."
	@echo "Targets:"
	@echo "  extract         - run hax to extract Rocq from Rust"
	@echo "  verify-abstract - compile only the hand-written AbstractCrypto.v"
	@echo "  clean           - remove generated files"
	@echo
	@echo "The maintained proof lives in proofs/fstar/. See proofs/README.md."
