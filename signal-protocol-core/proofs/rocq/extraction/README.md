# Signal Protocol Core - Rocq Verification

This directory contains the Rocq (formerly Coq) formal verification setup for the Signal Protocol core implementation.

## What is Rocq?

Rocq is the successor to the Coq Proof Assistant. It's an interactive theorem prover and dependently-typed programming language for mechanised reasoning. Coq was officially renamed to Rocq in March 2025.

Rocq uses `.v` files (same extension as Coq) and is fully backward compatible with most Coq code. The main command is now `rocq` instead of `coqc`, but `rocqq` (Rocq Make) can be used for parallel compilation.

## Prerequisites

1. **Install OPAM and OCaml**:

   ```bash
   sudo apt install opam
   opam init
   opam switch create 5.1.1
   eval $(opam env)
   ```

2. **Install Rocq**:

   ```bash
   opam install rocq-prover
   ```

3. **Install hax engine**:

   ```bash
   git clone https://github.com/hacspec/hax.git
   cd hax
   ./setup.sh
   eval $(opam env)
   ```

## Extracting Rocq from Rust

**Important**: Rocq extraction must be done WITHOUT the `crypto-backend` feature to get abstract crypto primitives.

```bash
cd signal-protocol-core

# Extract Rocq code without crypto backend (uses abstract crypto primitives)
# Note: Make sure to run `eval $(opam env)` first to have hax-engine in PATH
cargo-hax -C --no-default-features \; into coq --z3rlimit 40
```

This will generate Rocq files in `proofs/rocq/extraction/`.

### Alternative: Using Docker

```bash
docker compose run hax-rocq      # Extract Rocq
docker compose run rocq-verify    # Verify Rocq files
```

## Verifying the Rocq Code

```bash
cd proofs/rocq/extraction

# Verify all Rocq files (AbstractCrypto.v + extracted modules)
make verify

# Verify core modules only (Crypto, Keys, Error, Types, X3dh)
make verify-lite

# Or verify everything (extract + verify)
make
```

### Interactive Rocq Development

```bash
docker compose run rocq-shell

# Inside the shell
cd signal-protocol-core/proofs/rocq/extraction

# Run rocq in interactive mode
rocq AbstractCrypto.v

# Verify all files in parallel
rocq make -j$(nproc)
```

## Project Structure

```
signal-protocol-core/
├── src/
│   ├── lib.rs           # Main library entry
│   ├── crypto.rs        # Cryptographic primitives (abstract for Rocq)
│   ├── keys.rs          # Key generation functions
│   ├── x3dh.rs          # X3DH key exchange protocol
│   ├── double_ratchet.rs # Double Ratchet protocol
│   ├── types.rs         # Core data types
│   └── error.rs         # Error types
└── proofs/
    └── rocq/
        └── extraction/
            ├── AbstractCrypto.v      # Hand-written abstract crypto module
            ├── Makefile              # Build configuration
            ├── hax.coq.config.json   # Rocq configuration
            └── _CoqProject (generated) # Rocq project file
```

## Abstract Crypto Module (AbstractCrypto.v)

The `AbstractCrypto.v` module provides abstract models of cryptographic operations used in the Signal Protocol. These abstractions allow us to verify protocol properties without requiring full cryptographic proofs.

### Cryptographic Primitives as Axioms

- **Key Generation**: `generate_private_key` - Generate fresh random private keys
- **Public Key Derivation**: `public_key_of_private` - Derive public key from private key
- **Diffie-Hellman**: `dh` - X25519 key exchange
- **Signatures**: `sign` / `verify` - Ed25519 signature operations
- **Key Derivation**: `hkdf_derive` - HKDF key derivation function
- **Encryption**: `aead_encrypt` / `aead_decrypt` - AEAD encryption

### Security Axioms in AbstractCrypto.v

The module includes Coq/Rocq-style axioms for:

#### Key Generation Guarantees

- **Validity**: Generated private keys are always valid (32 bytes)
- **Public Key Derivation**: Preserves validity

#### DH Security

- **Commutativity**: `DH(a, B) = DH(b, A)` - Essential for key agreement
- **Determinism**: DH produces same result for identical inputs
- **Correctness**: DH produces 32-byte shared secret for valid inputs

#### Signature Security

- **Correctness**: Valid signatures verify correctly with matching public key
- **Length**: Signatures are 64 bytes (Ed25519)
- **Unforgeability**: Verification rejects signatures from wrong keys

#### Key Properties

- **Injectivity**: Different private keys yield different public keys
- **Inverse**: Same public key implies same private key
- **Forward Secrecy**: Compromise of long-term key doesn't reveal past DH secrets

#### HKDF & AEAD Security

- **Output Length**: HKDF produces output of requested length
- **Determinism**: Same inputs produce same outputs
- **Round-trip**: Decoding encryption recovers original plaintext (AEAD)

#### X3DH Key Agreement

- **Key Agreement**: X3DH produces matching shared secrets for initiator and responder
- **One-time Prekey**: X3DH with optional one-time prekey also produces matching secrets

## Hax Configuration

The `hax.coq.config.json` file configures hax's Rocq backend. It specifies:

1. **Rocq Command**: `rocq` (or alternative via CLI)
2. **Include Paths**: Paths to hax-libs and other dependencies
3. **Compilation Options**: Speed up verification with `-q -w -native-compiler no`

## Comparison: F\* vs Rocq

| Feature        | F\*                       | Rocq                                |
| -------------- | ------------------------- | ----------------------------------- |
| File Extension | `.fst`                    | `.v`                                |
| Compiler       | `fstar.exe`               | `rocq`                              |
| Parallel Build | `--cache_checked_modules` | `rocq make -j`                      |
| Axioms         | `assume`                  | `Parameter` and `Axiom`             |
| Types          | Dependent types           | Dependent types (more expressive)   |
| Learning Curve | Steep (SMT-based)         | Moderate (tactic-based proofs)      |
| Community      | Smaller, crypto-focused   | Larger (40+ years, CompCert, Prosa) |

## Security Properties to Prove

### X3DH

Already proven in AbstractCrypto.v:

- Key authentication
- Forward secrecy
- Key indistinguishability
- Mutual key agreement

### Double Ratchet

Future work to prove:

- Message key uniqueness
- Forward secrecy after compromise
- Chain key integrity
- Out-of-order message handling

## Common Issues and Solutions

### "No rocq in PATH"

Make sure Rocq is installed and in your PATH:

```bash
eval $(opam env)
```

### Extraction fails with cryptic errors

1. Ensure you're using `--no-default-features` to disable crypto-backend
2. Check that `hax-lib` is added to `Cargo.toml` as a dependency
3. Run `cargo hax --version` to ensure hax is properly installed

### Verification hangs or takes too long

1. Use `make verify-lite` to verify only core modules
2. Set `TIMEOUT` environment variable: `TIMEOUT=300s make verify`
3. Try `rocq make -j4` for parallel compilation (adjust number based on cores)

### "Unbound module" errors

Check that `_CoqProject` file includes correct include paths for hax-libs:

```bash
cat _CoqProject
```

## Docker Support

Using the Docker setup (recommended):

```bash
docker compose run rocq-shell

# Then inside the container
cd signal-protocol-core/proofs/rocq/extraction
make verify
```

## References

- [hax documentation](https://hax.cryspen.com)
- [Rocq Prover documentation](https://rocq-prover.org)
- [hax manual - Rocq backend](https://hax.cryspen.com/manual)
- [Signal Protocol specification](https://signal.org/docs/)
- [ProVerif proofs](../../formal-proofs/proverif/) - Existing ProVerif security proofs

## Migration from Coq

If you have existing Coq projects:

1. **Install Rocq** instead of Coq: `opam install rocq-prover`
2. **Update commands**:
   - `coqc` → `rocq`
   - `coqmakefile` → `rocq make` (in `_CoqProject` directory)
3. **Update shebangs**: `#! /usr/bin/env coqtop -compile` → `#! /usr/bin/env rocq`

Rocq is fully backward compatible with standard Coq code. The standard library has been split into `rocq-core` and `rocq-stdlib` packages.
