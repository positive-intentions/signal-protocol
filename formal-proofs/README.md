# Signal Protocol Formal Verification

This directory contains formal verification models of the Signal Protocol using PROVERIF. These models help verify that the implementation correctly handles key exchanges and protects against common cryptographic attacks.

## Quick Start

```bash
# Install PROVERIF
opam install proverif
export PATH="$HOME/.opam/default/bin:$PATH"

# Run all proofs
./test_proverif.sh
```

## What's Verified

### X3DH Handshake (`x3dh/*.pv`)

Verifies the initial key exchange between Alice and Bob:

- Up to 4 Diffie-Hellman operations execute in the correct order (DH4 is optional for additional forward secrecy)
- The shared secret can only be derived by parties with the correct private keys
- HKDF key derivation produces consistent outputs for both parties

### Double Ratchet (`double_ratchet/*.pv`)

Verifies ongoing message security:

- Forward secrecy: If a key is compromised, past messages remain secure
- Post-compromise security: After a compromise, new messages become secure again
- Message authentication: Only messages encrypted by the sender can be decrypted by the intended recipient

### End-to-End (`signal_protocol_complete.pv`)

Combines X3DH and Double Ratchet in a single model. Note: This model doesn't link the X3DH handshake to the Double Ratchet phase with a channel, so it doesn't prove the full end-to-end correspondence.

## Models

| File                                              | Purpose                                                     |
| ------------------------------------------------- | ----------------------------------------------------------- |
| `x3dh/x3dh_4dh.pv`                                | Demonstrates all 4 X3DH DH operations                       |
| `x3dh/x3dh_complete.pv`                           | Full X3DH handshake with HKDF constants from implementation |
| `x3dh/x3dh_security.pv`                           | Basic X3DH security properties                              |
| `double_ratchet/double_ratchet_dr.pv`             | DH ratchet state transitions                                |
| `double_ratchet/double_ratchet_key_derivation.pv` | Chain and message key derivation                            |
| `double_ratchet/double_ratchet_security.pv`       | Forward and post-compromise security                        |
| `signal_protocol_complete.pv`                     | Combined X3DH + Double Ratchet                              |

## Running Individual Models

```bash
proverif proverif/x3dh/x3dh_complete.pv
proverif proverif/double_ratchet/double_ratchet_security.pv
```

## Interpreting Results

ProVerif outputs show security queries and their results:

- **`RESULT not attacker(sk[]) is true`**: Secret keys are not accessible to the attacker
- **`RESULT not event(...) is false`**: The event fires (expected for normal protocol operations)
- **`RESULT inj-event(...) ==> inj-event(...) is true`**: Cryptographic correspondence (authentication)

## Documentation

- **[FORMAL_PROOF_STATUS.md](docs/FORMAL_PROOF_STATUS.md)**: Detailed results and model status
- **[VERIFICATION_GUIDE.md](docs/VERIFICATION_GUIDE.md)**: How to run and interpret proofs
- **[HKDF_CONSTANTS.md](docs/HKDF_CONSTANTS.md)**: HKDF constants from the implementation
- **[INSTALLATION.md](docs/INSTALLATION.md)**: PROVERIF setup instructions

## Implementation Alignment

The ProVerif models reference the Rust implementation:

- `src/rust/x3dh.rs`: X3DH DH operations and HKDF constants
- `src/rust/double_ratchet.rs`: Double Ratchet HKDF constants and AAD format

All DH operations, HKDF salts, info strings, and AAD formats match exactly what's in the code.
The ProVerif `hkdf(salt, ikm, info)` function signature models Rust's `Hkdf::new(salt, ikm).expand(info, output)` pattern.
