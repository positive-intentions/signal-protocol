# Experimental Verification Backends (Rocq, Lean)

> **Status: experimental, not part of the verified claim.**
>
> These two tracks were retained for the future possibility of
> cross-validating the F* proofs against alternative theorem provers.
> They are NOT currently maintained at the same standard as the
> primary F* + ProVerif backend in
> [`../fstar/`](../fstar/) and
> [`../../formal-proofs/proverif/`](../../../../formal-proofs/proverif/).

## Classic extraction trees (still in-repo)

The **pre-refactor** extraction directories remain available for CI and
local runs that use the full Makefiles (patching, `verify` / `verify-lite`):

- `signal-protocol-core/proofs/coq/` — full Rocq extraction workflow
- `signal-protocol-core/proofs/lean/` — full Lean extraction workflow

GitHub Actions (optional, **experimental** — same status as this folder):

- `.github/workflows/verify-lean.yml` — `npm run verify:lean:lite`
- `.github/workflows/verify-lean-full.yml` — `npm run verify:lean`
- `.github/workflows/verify-rocq.yml` — `npm run verify:rocq:abstract`
- `.github/workflows/verify-rocq-full.yml` — `npm run verify:rocq`

These workflows pin hax using `hax-upstream.commit` at the repo root, like
the F* workflow.

## Why these are demoted

The hax Rocq and Lean backends require post-extraction text rewriting
to compile - the previous Makefiles carried ~70 lines of `sed`/`perl`
rewrites whose output was fragile across hax versions. In particular:

- The Rocq output of `Signal_protocol_core_Double_ratchet.v` had to
  be hand-stubbed (`Definition` rewritten to `Axiom`) because the
  monadic-bind `ControlFlow` patterns hax emits did not type-check.
- The Lean output needed multiple `format!` argument-arity rewrites
  per hax minor release.

Maintaining both backends to a "production" standard alongside F* was
a multi-year proposition for diminishing return: F* is the canonical
proof, ProVerif covers symbolic security, and Rocq/Lean would only
add a *different* proof of the same property.

## What is here

```
experimental/
├── coq/
│   ├── extraction/
│   │   ├── AbstractCrypto.v       # hand-written abstract crypto module (verifies stand-alone)
│   │   ├── Core_Extra.v           # bridge to hax core re-exports
│   │   ├── Makefile               # `extract` and `verify-abstract` only
│   │   └── hax.coq.config.json
│   └── README.md
└── lean/
    ├── extraction/
    │   ├── AbstractCrypto.lean    # hand-written abstract crypto module
    │   └── Makefile               # `extract` only
    ├── lakefile.toml
    └── lean-toolchain
```

## What is supported

- **Rocq** (`experimental/coq/`):
  - `make extract` – runs hax to (re-)generate the Rocq files.
  - `make verify-abstract` – compiles only `AbstractCrypto.v` (does
    not depend on hax extraction succeeding).
- **Lean** (`experimental/lean/`):
  - `make extract` – runs hax to (re-)generate the Lean file.
  - The hand-written `AbstractCrypto.lean` can be built with
    `lake build extraction.AbstractCrypto` from the `lean/` directory.

## What is NOT supported

- Verifying the hax-extracted modules end-to-end. PRs that bring the
  Rocq or Lean tracks back to a fully-verifying state are welcome.

## Where the maintained proofs are

- **Functional correctness** of the Rust implementation:
  [`../fstar/`](../fstar/) – F* via hax extraction.
- **Symbolic security** (forward secrecy, post-compromise security,
  authentication, end-to-end secrecy):
  [`../../../../formal-proofs/proverif/`](../../../../formal-proofs/proverif/)
  – four ProVerif models verified by `formal-proofs/test_proverif.sh`.
