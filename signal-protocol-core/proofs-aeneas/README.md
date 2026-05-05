# Signal Protocol Core - Aeneas Formal Verification

This directory contains formal verification setups for the Signal Protocol core
implementation using [Aeneas](https://github.com/AeneasVerif/aeneas), a
verification toolchain that translates Rust programs (via
[Charon](https://github.com/AeneasVerif/charon)) into pure lambda calculus
representations for proof assistants.

This is the **Aeneas** verification path, parallel to the
[hax-based verification](../proofs/) in `proofs/`. Both tools extract from the
same Rust source (`signal-protocol-core/src/`) but use different translation
approaches:

|                  | Hax                                            | Aeneas                                                                                          |
| ---------------- | ---------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| **Pipeline**     | `cargo hax into {fstar\|coq\|lean}` (one step) | `charon cargo --preset=aeneas` → `.llbc`, then `aeneas -backend {fstar\|coq\|lean}` (two steps) |
| **Rust nightly** | `nightly-2025-02-01`                           | `nightly-2026-02-07`                                                                            |
| **Intermediate** | None (direct)                                  | LLBC (Charon's intermediate representation)                                                     |
| **Translation**  | Preserves imperative structure                 | Functionalizes into pure lambda calculus                                                        |

## Prerequisites

1. **OPAM and OCaml 5.x**:

   ```bash
   opam init
   opam switch create 5.1.1
   eval $(opam env)
   ```

2. **Charon** (Rust → LLBC):

   ```bash
   git clone https://github.com/AeneasVerif/charon.git
   cd charon && make build-charon-rust
   ```

3. **Aeneas** (LLBC → F\*/Coq/Lean):

   ```bash
   git clone https://github.com/AeneasVerif/aeneas.git
   cd aeneas && make setup-charon && make
   ```

4. **Proof assistants**: F\*, Rocq, or Lean 4 (see `../proofs/README.md` for install)

## Extracting from Rust

Aeneas extraction is a two-step process:

### Step 1: Generate LLBC with Charon

```bash
cd signal-protocol-core
charon cargo --preset=aeneas
```

This produces `signal_protocol_core.llbc` in the crate directory.

### Step 2: Translate LLBC to proof assistant

```bash
# F*
aeneas -backend fstar signal_protocol_core.llbc

# Rocq/Coq
aeneas -backend coq signal_protocol_core.llbc

# Lean
aeneas -backend lean signal_protocol_core.llbc
```

### Using Makefiles

Each backend has a Makefile that automates both steps:

```bash
# F*
cd proofs-aeneas/fstar/extraction
make extract   # charon + aeneas
make verify    # extract + verify with F*

# Rocq/Coq
cd proofs-aeneas/coq/extraction
make extract
make verify

# Lean
cd proofs-aeneas/lean/extraction
make extract
make verify     # via lake build
```

## Project Structure

```
signal-protocol-core/proofs-aeneas/
├── README.md
├── fstar/
│   └── extraction/
│       ├── Makefile              # Extract (charon+aeneas) + verify
│       └── AbstractCrypto.fst    # Hand-written abstract crypto (aeneas style)
├── coq/
│   └── extraction/
│       ├── Makefile
│       └── AbstractCrypto.v
└── lean/
    ├── lean-toolchain            # leanprover/lean4:v4.28.1
    ├── lakefile.toml             # Lake build (requires aeneas from aeneas-upstream)
    └── extraction/
        ├── Makefile
        └── AbstractCrypto.lean
```

## Abstract Crypto Modules

Each backend has a hand-written `AbstractCrypto` module that axiomatizes
cryptographic primitives (DH, sign/verify, HKDF, AEAD) with security
properties. These mirror the hax AbstractCrypto modules but use the naming and
type conventions produced by Aeneas extraction.

## Docker Support

```bash
# Interactive aeneas shell
docker compose run aeneas-shell

# Extract F* via aeneas
docker compose run aeneas-fstar

# Verify Lean via aeneas
docker compose run aeneas-lean-verify
```

## References

- [Aeneas documentation](https://aeneasverif.github.io/aeneas/)
- [Charon documentation](https://aeneasverif.github.io/charon/)
- [Hax-based verification](../proofs/) - parallel verification using hax
