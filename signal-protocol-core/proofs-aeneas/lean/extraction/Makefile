# Makefile for Lean extraction of signal-protocol-core via Aeneas
#
# Prerequisites:
#  1. elan installed (Lean version manager)
#  2. lean and lake in PATH (via elan)
#  3. cargo, charon, aeneas in PATH
#  4. eval $(opam env) for OCaml environment
#
# Usage:
#   make          - Extract Lean from Rust and verify
#   make extract  - Only extract Lean (charon + aeneas, no verification)
#   make verify   - Verify all Lean files via lake
#   make verify-lite - Verify core modules only
#   make clean    - Clean generated files (keeps AbstractCrypto.lean)

AENEAS_HOME ?= $(abspath ../../../../aeneas-upstream)

SHELL ?= /usr/bin/env bash

EXECUTABLES = cargo charon aeneas lake
K := $(foreach bin,$(EXECUTABLES),\
        $(if $(shell command -v $(bin) 2>/dev/null),,$(error "No $(bin) in PATH")))

.PHONY: all verify verify-lite extract clean help

CRATE_DIR = ../../..
LLBC_FILE = $(CRATE_DIR)/signal_protocol_core.llbc

CHARON_CLI = cd $(CRATE_DIR) && charon cargo --preset=aeneas

AENEAS_CLI = aeneas -backend lean -o . $(LLBC_FILE)

MANUAL_LEAN = AbstractCrypto.lean

EXTRACTED_LEAN = $(filter-out $(MANUAL_LEAN),$(wildcard *.lean))

all: verify

extract:
	$(info Extracting LLBC with Charon...)
	$(CHARON_CLI)
	$(info Translating LLBC to Lean with Aeneas...)
	$(AENEAS_CLI)

verify: extract
	$(info Verifying Lean files...)
	cd .. && lake build

verify-lite: extract
	$(info Verifying core Lean modules only...)
	cd .. && lake build extraction.AbstractCrypto

clean:
	rm -f Signal_protocol_core*.lean
	rm -f $(LLBC_FILE)
	cd .. && rm -rf .lake lake-manifest.json

help:
	@echo "Aeneas Lean Verification for Signal Protocol Core"
	@echo ""
	@echo "Targets:"
	@echo "  all         - Extract and verify all Lean files (default)"
	@echo "  extract     - Extract Lean from Rust via charon + aeneas"
	@echo "  verify      - Verify all Lean files via lake build"
	@echo "  verify-lite - Verify core modules only"
	@echo "  clean       - Clean generated files"
	@echo "  help        - Show this help message"
	@echo ""
	@echo "Environment Variables:"
	@echo "  AENEAS_HOME - Path to aeneas repo (default: ../../aeneas-upstream)"
