# PROVERIF Installation Guide

## Overview

This guide explains how to install PROVERIF and set up the development environment for formal verification of the Signal Protocol implementation.

## Prerequisites

- OCaml (version 4.08 or later)
- opam (OCaml package manager)

## Installation Steps

### 1. Install OCaml and opam

```bash
# On Ubuntu/Debian
sudo apt-get install ocaml opam

# Initialize opam
opam init
eval $(opam env)
```

### 2. Install PROVERIF

```bash
opam install proverif
export PATH="$HOME/.opam/default/bin:$PATH"
```

### 3. Verify Installation

```bash
proverif -help | head -1
# Should output: Proverif 2.05. ...
```

## Running Proofs

### Quick Test

```bash
cd formal-proofs
./test_proverif_quick.sh          # Fast pass/fail check
./test_proverif.sh               # Detailed security analysis
```

### Run Specific Model

```bash
proverif proverif/x3dh/x3dh_complete.pv
```

## Troubleshooting

### Common Issues

1. **PROVERIF not found**: Ensure `~/.opam/default/bin` is in your PATH
2. **Compilation errors**: Check PROVERIF version (requires 2.05+)

### Getting Help

- PROVERIF documentation: https://proverif.inria.fr
