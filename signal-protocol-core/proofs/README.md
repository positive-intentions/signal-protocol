# Signal Protocol Core - Formal Verification

This directory contains formal verification setups for the Signal Protocol core implementation using F\*, Rocq (formerly Coq), Lean 4, and ProVerif.

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
    ├── fstar/
    │   └── extraction/
    │       ├── AbstractCrypto.fst    # Hand-written abstract crypto module
    │       ├── Makefile              # Build configuration
    │       └── hax.fst.config.json   # F* configuration
    ├── coq/
    │   └── extraction/
    │       ├── AbstractCrypto.v      # Hand-written abstract crypto module
    │       └── Makefile              # Build configuration
    └── lean/
        ├── lean-toolchain            # Lean version specification
        ├── lakefile.toml             # Lake build configuration
        └── extraction/
            ├── AbstractCrypto.lean   # Hand-written abstract crypto module
            └── Makefile              # Build configuration
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

**Note**: Rocq is the successor to Coq (renamed March 2025). Rocq uses `.v` files and provides a mature, well-documented theorem proving environment. The hax backend outputs to `proofs/coq/` which is compatible with both Coq and Rocq.

### Prerequisites

Install Rocq via OPAM:

```bash
opam install rocq-prover
```

### Extracting Rocq from Rust

**Important**: Rocq extraction must be done WITHOUT the `crypto-backend` feature to get abstract crypto primitives.

```bash
cd signal-protocol-core
cargo-hax -C --no-default-features \; into coq
```

### Verifying Rocq Code

```bash
cd proofs/coq/extraction
make verify              # Verify all modules
make verify-lite         # Verify core modules only (Crypto, Keys, Error, Types, X3dh)
make                    # Extract and verify everything
```

### Docker Commands

```bash
# Extract Rocq from Rust
docker compose run hax-coq

# Verify all Rocq files
docker compose run coq-verify

# Interactive Rocq shell
docker compose run coq-shell
```

### Rocq Project Structure

```
proofs/coq/extraction/
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

See [proofs/coq/README.md](coq/README.md) for detailed Rocq verification setup including:

- Complete setup instructions
- Common issues and solutions
- Migration guide from Coq
- Interactive development workflow
- Detailed security properties

References:

- [Rocq Prover documentation](https://rocq-prover.org)
- [ROCQ / Coq migration guide](https://rocq-prover.org)
- [hax Rocq backend](https://hax.cryspen.com)

---

## Lean Verification

Lean 4 is a functional programming language and theorem prover developed by Leonardo de Moura at Microsoft Research. The hax backend supports extraction to Lean 4, enabling verification using Lean's powerful tactic system and automation.

### Prerequisites

Install Lean via elan (Lean version manager):

```bash
# Install elan
curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh -s -- -y

# Source elan
source $HOME/.elan/env

# Verify installation
lean --version
lake --version
```

### Extracting Lean from Rust

**Important**: Lean extraction must be done WITHOUT the `crypto-backend` feature to get abstract crypto primitives.

```bash
cd signal-protocol-core
cargo-hax -C --no-default-features \; into lean
```

This will generate Lean files in `proofs/lean/extraction/`.

### Verifying Lean Code

```bash
cd proofs/lean

# Build all Lean files
lake build

# Or use Makefile
cd extraction
make verify        # Extract and verify all
make verify-lite   # Verify core modules only
make extract       # Extract only (no verification)
```

### Docker Commands

```bash
# Extract Lean from Rust
docker compose run hax-lean

# Verify all Lean files
docker compose run lean-verify

# Interactive Lean shell
docker compose run lean-shell
```

### Lean Project Structure

```
proofs/lean/
├── lean-toolchain           # Lean version specification
├── lakefile.toml            # Lake build configuration
├── lake-manifest.json       # Dependency manifest (generated)
└── extraction/
    ├── AbstractCrypto.lean  # Hand-written abstract crypto module
    ├── Makefile             # Extraction automation
    └── Signal_protocol_core*.lean  # Extracted Lean files
```

### Abstract Crypto Module (Lean Version)

The `AbstractCrypto.lean` module provides abstract models of cryptographic operations:

- **Key Operations**: `generatePrivateKey`, `publicKeyOfPrivate`
- **Diffie-Hellman**: `dh` - X25519 key exchange
- **Signatures**: `sign`, `verify` - Ed25519 signatures
- **Key Derivation**: `hkdfDerive` - HKDF key derivation
- **Encryption**: `aeadEncrypt`, `aeadDecrypt` - AEAD encryption

### Security Axioms in Lean

The module includes Lean-style axioms for:

- **Key Generation**: Valid keys, public key derivation
- **DH Security**: Commutativity, determinism, correctness
- **Signature Security**: Correctness, unforgeability
- **Key Properties**: Injectivity, inverse, forward secrecy
- **HKDF/AEAD**: Output length, determinism, round-trip
- **X3DH**: Key agreement properties

### Comparison: F\* vs Rocq vs Lean

| Aspect         | F\*                     | Rocq                                | Lean 4                                |
| -------------- | ----------------------- | ----------------------------------- | ------------------------------------- |
| File Extension | `.fst`                  | `.v`                                | `.lean`                               |
| Command        | `fstar.exe`             | `rocq`                              | `lake build`                          |
| Build System   | Makefile + F\* cache    | Makefile + rocqmake                 | Lake (built-in)                       |
| Proof Style    | SMT/Z3 automated        | Tactic-based                        | Tactic-based + `grind` automation     |
| Automation     | Z3 SMT solver           | `auto`, `lia`, `ring`               | `simp`, `grind`, `omega`, `bv_decide` |
| Community      | Crypto-focused, smaller | Very large, mature                  | Rapidly growing, Mathlib              |
| Learning Curve | Steep                   | Moderate                            | Moderate                              |
| Math Library   | Limited                 | Extensive (Mathematical Components) | Mathlib4 (very extensive)             |

### Lean-Specific Features

Lean 4 offers several advantages for verification:

1. **Powerful Automation**: The `grind` tactic provides SMT-like automation
2. **Mathlib4**: Access to extensive mathematical library
3. **Modern Tooling**: Built-in build system (Lake), LSP support, VS Code integration
4. **Expressive Language**: Dependent types, type classes, metaprogramming

### Adding Proof Annotations

To generate verification conditions in Lean, add hax annotations to your Rust code:

```rust
#[hax_lib::requires(x < 16)]
#[hax_lib::ensures(|res| true)]
fn square(x: u8) -> u8 {
    x * x
}
```

After extraction, Lean will generate proof obligations that can be discharged using tactics.

### Interactive Development

For interactive proof development:

1. Open `proofs/lean/` in VS Code with the Lean 4 extension
2. The extension provides real-time feedback on proof states
3. Use `#check` and `#print` commands to explore definitions

References:

- [Lean 4 documentation](https://lean-lang.org)
- [Mathlib4 documentation](https://github.com/leanprover-community/mathlib4)
- [hax Lean backend](https://hax.cryspen.com)
- [Lean 4 manual](https://lean-lang.org/doc/reference/latest/)
