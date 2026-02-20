# Signal Protocol Core - Formal Verification

This directory contains formal verification setups for the Signal Protocol core implementation using F\*, Rocq (formerly Coq), and ProVerif.

## Prerequisites

1. **Install OPAM and OCaml**:

   ```bash
   # Install opam (OCaml package manager)
   # On Ubuntu/Debian:
   sudo apt install opam

   # Initialize opam
   opam init
   opam switch create 5.1.1
   eval $(opam env)
   ```

2. **Install F\***:

   ```bash
   opam install fstar
   ```

3. **Install hax engine**:

   ```bash
   # Clone and build hax engine
   git clone https://github.com/hacspec/hax.git
   cd hax
   ./setup.sh
   eval $(opam env)
   ```

4. **Install other tools**:
   ```bash
   # Required tools
   # - cargo (rustup)
   # - nodejs
   # - jq
   ```

## Extracting F\* from Rust

**Important**: F\* extraction must be done WITHOUT the `crypto-backend` feature to get abstract crypto primitives.

```bash
# From the signal-protocol-core directory
cd signal-protocol-core

# Extract F* code without crypto backend (uses abstract crypto primitives)
# Note: Make sure to run `eval $(opam env)` first to have hax-engine in PATH
cargo-hax -C --no-default-features \; into fstar --z3rlimit 40
```

This will generate F\* files in `proofs/fstar/extraction/`.

### Alternative: Using Makefile

```bash
cd proofs/fstar/extraction
make extract  # Extract only (no verification)
make          # Extract and verify
```

## Verifying the F\* Code

```bash
cd proofs/fstar/extraction

# Verify all F* files (AbstractCrypto.fst + extracted modules)
make verify

# Or verify everything (extract + verify)
make
```

## Project Structure

```
signal-protocol-core/
├── src/
│   ├── lib.rs           # Main library entry
│   ├── crypto.rs        # Cryptographic primitives (abstract for F*)
│   ├── keys.rs          # Key generation functions
│   ├── x3dh.rs          # X3DH key exchange protocol
│   ├── double_ratchet.rs # Double Ratchet protocol
│   ├── types.rs         # Core data types
│   └── error.rs         # Error types
└── proofs/
    └── fstar/
        └── extraction/
            ├── AbstractCrypto.fst    # Hand-written abstract crypto module
            ├── Makefile              # Build configuration
            └── hax.fst.config.json   # F* configuration
```

## Hax Annotations

The Rust code uses hax attributes to control extraction:

- `#[hax_lib::include]` - Include this function in F\* extraction
- `#[hax_lib::fstar::replace(...)]` - Replace with custom F\* code

### Crypto Abstractions

Cryptographic primitives are abstracted in `AbstractCrypto.fst`:

- `generate_private_key` - Generate a fresh private key
- `public_key_of_private` - Derive public key from private key
- `dh` - Diffie-Hellman key exchange
- `sign` / `verify` - Ed25519 signature operations
- `hkdf_derive` - HKDF key derivation
- `aead_encrypt` / `aead_decrypt` - AEAD encryption

These are modeled as uninterpreted functions in F\* with security axioms.

## Security Axioms in AbstractCrypto.fst

The `AbstractCrypto.fst` module includes security axioms:

### DH Security

- **Commutativity**: `DH(a, B) = DH(b, A)` - Essential for key agreement
- **Indistinguishability**: DH outputs look random to attackers

### Signature Security

- **Correctness**: Valid signatures verify correctly
- **Unforgeability**: Only private key holder can create valid signatures

### Key Properties

- **Forward Secrecy**: Compromise of long-term key doesn't reveal past secrets
- **Key Indistinguishability**: Fresh keys look random to attackers

## Security Properties to Prove

### X3DH

- Key authentication
- Forward secrecy
- Key indistinguishability
- Mutual key agreement

### Double Ratchet

- Message key uniqueness
- Forward secrecy after compromise
- Chain key integrity
- Out-of-order message handling

## Docker Support

Using the Docker setup (recommended):

```bash
# Start interactive shell with all tools
docker compose run formal-shell

# Then inside the container
cd signal-protocol-core/proofs/fstar/extraction
make
```

## References

- [hax documentation](https://hax.cryspen.com)
- [F\* documentation](https://www.fstar-lang.org)
- [Signal Protocol specification](https://signal.org/docs/)
- [ProVerif proofs](../../formal-proofs/proverif/) - Existing ProVerif security proofs

---

## Rocq Verification

**Note**: Rocq is the successor to Coq (renamed March 2025). Rocq uses `.v` files and provides a mature, well-documented theorem proving environment.

### Prerequisites

Install Rocq via OPAM:

```bash
opam install rocq-prover
```

### Extracting Rocq from Rust

**Important**: Rocq extraction must be done WITHOUT the `crypto-backend` feature to get abstract crypto primitives.

```bash
cd signal-protocol-core
cargo-hax -C --no-default-features \; into coq --z3rlimit 40
```

### Verifying Rocq Code

```bash
cd proofs/rocq/extraction
make verify              # Verify all modules
make verify-lite         # Verify core modules only (Crypto, Keys, Error, Types, X3dh)
make                    # Extract and verify everything
```

### Docker Commands

```bash
# Extract Rocq from Rust
docker compose run hax-rocq

# Verify all Rocq files
docker compose run rocq-verify

# Interactive Rocq shell
docker compose run rocq-shell
```

### Rocq Project Structure

```
proofs/rocq/extraction/
├── AbstractCrypto.v          # Hand-written abstract crypto module
├── Makefile                  # Build configuration
├── hax.coq.config.json       # Rocq configuration for hax
└── Signal_protocol_core*.v   # Extracted Rocq files
```

### Abstract Crypto Module (Rocq Version)

The `AbstractCrypto.v` module provides abstract models of cryptographic operations:

- **Key Operations**: `generate_private_key`, `public_key_of_private`
- **Diffie-Hellman**: `dh` - X25519 key exchange
- **Signatures**: `sign`, `verify` - Ed25519 signatures
- **Key Derivation**: `hkdf_derive` - HKDF key derivation
- **Encryption**: `aead_encrypt`, `aead_decrypt` - AEAD encryption

### Security Axioms in Rocq

The module includes Coq/Rocq-style axioms for:

- **Key Generation**: Valid keys, public key derivation
- **DH Security**: Commutativity, determinism, correctness
- **Signature Security**: Correctness, unforgeability
- **Key Properties**: Injectivity, inverse, forward secrecy
- **HKDF/AEAD**: Output length, determinism, round-trip

### Comparison: F\* vs Rocq

| Aspect         | F\*                                      | Rocq                                                      |
| -------------- | ---------------------------------------- | --------------------------------------------------------- |
| File Extension | `.fst`                                   | `.v`                                                      |
| Command        | `fstar.exe`                              | `rocq`                                                    |
| Compilation    | `--cache_checked_modules`                | `rocq make -j`                                            |
| Proof Style    | SMT/Z3 automated (with refinement types) | Tactic-based (LEMM, apply, induction)                     |
| Community      | Crypto-focused, smaller                  | Very large, mature (CompCert, Mathematical formalization) |
| Learning Curve | Steep                                    | Moderate                                                  |

### Rocq Documentation

See [proofs/rocq/README.md](rocq/README.md) for detailed Rocq verification setup including:

- Complete setup instructions
- Common issues and solutions
- Migration guide from Coq
- Interactive development workflow
- Detailed security properties

References:

- [Rocq Prover documentation](https://rocq-prover.org)
- [ROCQ / Coq migration guide](https://rocq-prover.org)
- [hax Rocq backend](https://hax.cryspen.com)
