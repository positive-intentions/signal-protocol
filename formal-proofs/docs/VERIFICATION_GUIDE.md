# Verification Guide: Running and Interpreting PROVERIF Proofs

## Overview

This guide explains how to run the PROVERIF proofs for the Signal Protocol implementation and interpret the results.

## Prerequisites

Before running proofs, ensure you have:

1. **PROVERIF installed** (see `INSTALLATION.md`)
2. **OPAM environment** set up correctly
3. **Test scripts** from the project root

## Running Proofs

### Quick Test Scripts

```bash
cd /home/raju/repos/positive-intentions/signal-protocol
./test_proverif_quick.sh          # Fast pass/fail check (5 seconds)
./test_proverif.sh               # Detailed security analysis
```

### Running Individual Models

```bash
proverif proverif/x3dh/x3dh_complete.pv
proverif proverif/double_ratchet/double_ratchet_security.pv
```

## Interpreting Results

### Successful Proof

A successful proof shows the model compiles and security properties are verified:

```
RESULT not attacker(sk[]) is true.      # Key secrecy proved
```

### Expected "False" Results

Some queries return `false` by design - this means the event executes:

```
RESULT not event(dh1_computed(x_1)) is false.  # Event executes (expected)
```

### Proof Status Examples

| Property                  | Expected Result | Meaning                        |
| ------------------------- | --------------- | ------------------------------ |
| Key secrecy               | ✅ `true`       | Private keys aren't accessible |
| Events firing             | ❌ `false`      | Event executes (expected)      |
| Correspondence (unlinked) | ❌ `false`      | No channel linking (expected)  |

## Security Properties Verified

All 7 PROVERIF models prove:

| Property                 | Status    |
| ------------------------ | --------- |
| All 4 X3DH DH operations | ✅ PROVED |
| Key secrecy              | ✅ PROVED |
| Forward secrecy          | ✅ PROVED |
| Post-compromise security | ✅ PROVED |
| Message authentication   | ✅ PROVED |

## Troubleshooting

### PROVERIF Not Found

```bash
opam install proverif
export PATH="$HOME/.opam/default/bin:$PATH"
```

### Compilation Errors

Check PROVERIF version - requires 2.05+.

## Documentation

- **Proof results**: [FORMAL_PROOF_STATUS.md](FORMAL_PROOF_STATUS.md)
- **Installation**: [INSTALLATION.md](INSTALLATION.md)
