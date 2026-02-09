# Signal Protocol Formal Verification

## Overview

This directory contains formal verification models of the Signal Protocol using PROVERIF.

## Quick Start

### Installation

```bash
# Install PROVERIF
opam install proverif
export PATH="$HOME/.opam/default/bin:$PATH"
```

### Running the Proofs

```bash
# Test all models (fast check)
./test_proverif_quick.sh

# Detailed analysis with security properties
./test_proverif.sh

# Test specific model
proverif proverif/x3dh/x3dh_complete.pv
```

## Models

```
formal-proofs/proverif/
├── x3dh/
│   ├── x3dh_4dh.pv              # All 4 X3DH DH operations
│   ├── x3dh_complete.pv        # Complete X3DH with HKDF constants
│   └── x3dh_security.pv        # X3DH security properties
├── double_ratchet/
│   ├── double_ratchet_dr.pv    # State transitions
│   ├── double_ratchet_key_derivation.pv  # Key derivation chain
│   └── double_ratchet_security.pv       # FS and PCS proofs
└── signal_protocol_complete.pv          # End-to-end X3DH + DR
```

## Security Properties Proven

| Property                  | Status    | Notes                                  |
| ------------------------- | --------- | -------------------------------------- |
| Key Secrecy               | ✅ PROVED | Private keys inaccessible to attacker  |
| X3DH: All 4 DH Operations | ✅ PROVED | Modeled correctly (DH1-DH4)            |
| X3DH: HKDF Key Derivation | ✅ PROVED | With implementation constants          |
| Forward Secrecy           | ✅ PROVED | Old keys secure after state updates    |
| Post-Compromise Security  | ✅ PROVED | System recovers after compromise       |
| Message Authentication    | ✅ PROVED | Encryption ⇒ decryption correspondence |

## Proof Results

All 7 PROVERIF models compile and prove security properties:

```
Total: 7 models
Passed: 7 models
Failed: 0 models
Success Rate: 100%
```

Full breakdown: See [docs/PROOF_RESULTS.md](docs/PROOF_RESULTS.md)

## Documentation

| Document                                              | Purpose                              |
| ----------------------------------------------------- | ------------------------------------ |
| [FORMAL_PROOF_STATUS.md](docs/FORMAL_PROOF_STATUS.md) | Proof results and model status       |
| [VERIFICATION_GUIDE.md](docs/VERIFICATION_GUIDE.md)   | How to run and interpret proofs      |
| [INSTALLATION.md](docs/INSTALLATION.md)               | PROVERIF installation instructions   |
| [HKDF_CONSTANTS.md](docs/HKDF_CONSTANTS.md)           | Implementation constants from source |

## Implementation References

Proofs reference implementation at:

- `src/rust/x3dh.rs` (DH operations, HKDF constants)
- `src/rust/double_ratchet.rs` (HKDF constants, AAD format)

## Why PROVERIF?

## License

Part of Signal Protocol implementation. See project root for license information.
