# Makefile for F* extraction of signal-protocol-core via Aeneas
#
# Prerequisites:
#  1. fstar.exe in PATH (or set $FSTAR_HOME)
#  2. cargo, rustup, charon, aeneas in PATH
#  3. eval $(opam env) for OCaml/F* environment
#
# Usage:
#   make          - Extract F* from Rust and verify
#   make extract  - Only extract F* (charon + aeneas, no verification)
#   make verify   - Full verification (includes Double_ratchet)
#   make verify-lite - Verify core modules only (skips Double_ratchet)
#   make clean    - Clean generated files (keeps AbstractCrypto.fst)

AENEAS_HOME    ?= $(abspath ../../../../aeneas-upstream)
FSTAR_BIN      ?= fstar.exe
CACHE_DIR      ?= .cache
HINT_DIR       ?= .hints

SHELL ?= /usr/bin/env bash

EXECUTABLES = cargo charon aeneas
K := $(foreach bin,$(EXECUTABLES),\
        $(if $(shell command -v $(bin) 2>/dev/null),,$(error "No $(bin) in PATH")))

.PHONY: all verify verify-lite extract clean help

all:
	rm -f .depend && $(MAKE) .depend
	$(MAKE) verify

CRATE_DIR = ../../..
LLBC_FILE = $(CRATE_DIR)/signal_protocol_core.llbc

CHARON_CLI = cd $(CRATE_DIR) && charon cargo --preset=aeneas

AENEAS_CLI = aeneas -backend fstar -o . $(LLBC_FILE)

MANUAL_FST = AbstractCrypto.fst

EXTRACTED_FST = $(filter-out $(MANUAL_FST),$(wildcard *.fst))

ROOTS = $(MANUAL_FST) $(EXTRACTED_FST)

ROOTS_LITE = $(filter-out %Double_ratchet.fst,$(ROOTS))

AENEAS_PROOF_LIBS = $(AENEAS_HOME)/backends/fstar

FSTAR_INCLUDE_DIRS = . \
  $(AENEAS_PROOF_LIBS)

FSTAR_FLAGS = --cmi \
  --warn_error -331 \
  --z3version 4.13.3 \
  --z3rlimit 100 \
  --z3refresh \
  --cache_checked_modules --cache_dir $(CACHE_DIR) \
  --already_cached "+Prims+FStar+LowStar+C+Spec.Loops+TestLib" \
  $(addprefix --include ,$(FSTAR_INCLUDE_DIRS))

FSTAR = $(FSTAR_BIN) $(FSTAR_FLAGS)

TIMEOUT ?= 600s

.depend: $(HINT_DIR) $(CACHE_DIR) $(ROOTS)
	$(info ROOTS: $(ROOTS))
	$(FSTAR) --cmi --dep full $(ROOTS) --extract '* -Prims -LowStar -FStar' > $@.tmp
	mv $@.tmp $@

include .depend

$(HINT_DIR):
	mkdir -p $@

$(CACHE_DIR):
	mkdir -p $@

$(CACHE_DIR)/%.checked: | .depend $(HINT_DIR) $(CACHE_DIR)
	timeout $(TIMEOUT) $(FSTAR) $(OTHERFLAGS) $* $(ENABLE_HINTS) --hint_file $(HINT_DIR)/$(notdir $*).hints

verify: $(addsuffix .checked, $(addprefix $(CACHE_DIR)/,$(ROOTS)))

verify-lite: $(addsuffix .checked, $(addprefix $(CACHE_DIR)/,$(ROOTS_LITE)))

extract:
	$(info Extracting LLBC with Charon...)
	$(CHARON_CLI)
	$(info Translating LLBC to F* with Aeneas...)
	$(AENEAS_CLI)

clean:
	rm -rf $(CACHE_DIR) $(HINT_DIR) .depend
	rm -f Signal_protocol_core*.fst Signal_protocol_core*.fsti
	rm -f $(LLBC_FILE)

help:
	@echo "Aeneas F* Verification for Signal Protocol Core"
	@echo ""
	@echo "Targets:"
	@echo "  all         - Extract and verify all F* files (default)"
	@echo "  verify      - Verify all F* files"
	@echo "  verify-lite - Verify core modules only (skips Double_ratchet)"
	@echo "  extract     - Extract F* from Rust via charon + aeneas"
	@echo "  clean       - Clean generated files"
	@echo "  help        - Show this help message"
	@echo ""
	@echo "Environment Variables:"
	@echo "  AENEAS_HOME - Path to aeneas repo (default: ../../aeneas-upstream)"
	@echo "  FSTAR_BIN   - F* binary (default: fstar.exe)"
	@echo "  TIMEOUT     - Per-module timeout (default: 600s)"
