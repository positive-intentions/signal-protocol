# Makefile for Rocq/Coq extraction of signal-protocol-core via Aeneas
#
# Prerequisites:
#  1. rocq or coqc in PATH (or set $ROCQ_BIN)
#  2. cargo, rustup, charon, aeneas in PATH
#  3. eval $(opam env) for OCaml/Rocq environment
#
# Usage:
#   make          - Extract and verify all Rocq files (default)
#   make verify   - Verify all Rocq files
#   make verify-lite - Verify core modules only (skips Double_ratchet)
#   make verify-abstract - Verify only AbstractCrypto.v
#   make extract  - Only extract Rocq from Rust (no verification)
#   make clean    - Clean generated files (keeps AbstractCrypto.v)

AENEAS_HOME ?= $(abspath ../../../../aeneas-upstream)
ROCQ_BIN    ?= rocq

SHELL ?= /usr/bin/env bash

EXECUTABLES = cargo charon aeneas
K := $(foreach bin,$(EXECUTABLES),\
        $(if $(shell command -v $(bin) 2>/dev/null),,$(error "No $(bin) in PATH")))

.PHONY: all verify verify-lite verify-abstract extract clean help

ROCQ_IS_MODERN := $(shell $(ROCQ_BIN) compile --help >/dev/null 2>&1 && echo yes || echo no)

CRATE_DIR = ../../..
LLBC_FILE = $(CRATE_DIR)/signal_protocol_core.llbc

CHARON_CLI = cd $(CRATE_DIR) && charon cargo --preset=aeneas

AENEAS_CLI = aeneas -backend coq -o . $(LLBC_FILE)

MANUAL_V = AbstractCrypto.v

EXTRACTED_V = $(filter-out $(MANUAL_V),$(wildcard *.v))

ROOTS = $(MANUAL_V) $(EXTRACTED_V)

ROCQ_FLAGS = -q -w -native-compiler=no
ROCQ_INCLUDE_DIRS = -R . Signal_protocol_core

ifneq ($(wildcard $(AENEAS_HOME)/backends/coq),)
  ROCQ_INCLUDE_DIRS += -R $(AENEAS_HOME)/backends/coq Aeneas
endif

ifeq ($(ROCQ_IS_MODERN),yes)
  ROCQ = $(ROCQ_BIN) compile $(ROCQ_FLAGS) $(ROCQ_INCLUDE_DIRS)
else
  ROCQ = $(ROCQ_BIN) $(ROCQ_FLAGS) $(ROCQ_INCLUDE_DIRS)
endif

TIMEOUT ?= 600s

all: verify

verify: extract
	$(info Verifying Rocq files...)
	@echo "Compiling AbstractCrypto.v..."
	@timeout $(TIMEOUT) $(ROCQ) AbstractCrypto.v || exit 1
	@for f in $(EXTRACTED_V); do \
		echo "Compiling $$f..."; \
		timeout $(TIMEOUT) $(ROCQ) $$f || exit 1; \
	done

verify-lite: extract
	$(info Verifying core Rocq modules only...)
	@echo "Compiling AbstractCrypto.v..."
	@timeout $(TIMEOUT) $(ROCQ) AbstractCrypto.v || exit 1
	@for f in $(filter-out %Double_ratchet.v,$(EXTRACTED_V)); do \
		echo "Compiling $$f..."; \
		timeout $(TIMEOUT) $(ROCQ) $$f || exit 1; \
	done

verify-abstract:
	$(info Verifying AbstractCrypto.v only...)
	@echo "Compiling AbstractCrypto.v..."
	@timeout $(TIMEOUT) $(ROCQ_BIN) compile -q -w -native-compiler=no -R . Signal_protocol_core AbstractCrypto.v || \
	timeout $(TIMEOUT) $(ROCQ_BIN) -q -w -native-compiler=no -R . Signal_protocol_core AbstractCrypto.v
	@echo "AbstractCrypto.v verified successfully"

extract:
	$(info Extracting LLBC with Charon...)
	$(CHARON_CLI)
	$(info Translating LLBC to Rocq with Aeneas...)
	$(AENEAS_CLI)

clean:
	rm -f *.vo *.glob *.vok *.vos .*.aux *.aux
	rm -f Signal_protocol_core*.v
	rm -f $(LLBC_FILE)

help:
	@echo "Aeneas Rocq Verification for Signal Protocol Core"
	@echo ""
	@echo "Targets:"
	@echo "  all             - Extract and verify all Rocq files (default)"
	@echo "  verify          - Verify all Rocq files"
	@echo "  verify-lite     - Verify core modules only (skips Double_ratchet)"
	@echo "  verify-abstract - Verify only AbstractCrypto.v"
	@echo "  extract         - Extract Rocq from Rust via charon + aeneas"
	@echo "  clean           - Clean generated files"
	@echo "  help            - Show this help message"
	@echo ""
	@echo "Environment Variables:"
	@echo "  AENEAS_HOME - Path to aeneas repo (default: ../../aeneas-upstream)"
	@echo "  ROCQ_BIN    - Rocq/Coq binary (default: rocq)"
	@echo "  TIMEOUT     - Per-module timeout (default: 600s)"
