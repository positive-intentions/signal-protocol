# Signal Protocol Core - F\* Verification

This directory contains the F\* formal verification setup for the Signal Protocol core implementation.

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
