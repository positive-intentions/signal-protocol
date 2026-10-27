# SP-2026 — signal-protocol library security review

| Field | Value |
| --- | --- |
| Date | 27 October 2026 |
| Subject | `signal-protocol-core` (X3DH + Double Ratchet) and WASM bindings in this repository |
| Method | Static review against Signal X3DH / Double Ratchet / XEdDSA specifications; runtime probes; cascade product review |
| Status | Findings **Mitigated** in-tree (hard break: regenerate identities / re-pair / re-sign prekeys). Still **not** an independent firm audit |
| Not claimed | Safety of the Glitr messenger; anonymity; Signal-app wire compatibility |

Related artefacts:

- Positive regressions: [`signal-protocol-core/tests/audit_probes.rs`](../signal-protocol-core/tests/audit_probes.rs)
- Behavioural specs (Allium): [`specs/signal-protocol-core.allium`](../specs/signal-protocol-core.allium)
- Formal verification: [`formal-proofs/proverif/`](../formal-proofs/proverif/) (incl. `sp2026_hardening.pv`); hax extracts under `signal-protocol-core/proofs/`
- XEdDSA interop: [`xeddsa-interop/`](../xeddsa-interop/) (+ checked-in `vectors.json`)
- Consumers: `pqxdh-core`, `crypto-cascade`, `api-core`
- Public docs: [Behavioural specs](https://positive-intentions.com/docs/technical/formal-verification/behavioural-specs)

## Executive summary

SP-2026-001–017 are **mitigated** in this repository and companion crates:

- Double Ratchet: commit-after-AEAD, `PN` previous-chain skip, FIFO skipped-key bounds, counter overflow checks
- X3DH: SPK verify inside initiate; AD = `IK_A || IK_B` into every seal/open
- Identity: XEdDSA on a single X25519 key, **Signal-spec** encoding/verify (**hard break**)
- Fail-closed init: single typed `initialize_double_ratchet(…, RatchetRole)`; empty AD / missing SPK rejected; legacy WASM encrypt/decrypt removed
- Product (crypto-cascade): decrypt clone-commit; Signal handshake wire **v4** binds OTPK id (single-use); PQXDH OTPK by id; prekey re-sign on load (Signal + PQXDH SPK/PQ)
- Formal: ProVerif models encode SPK check, IK AD, commit-after-auth, OTPK once; hax re-extracted

The library remains **research-grade** (not firm-audited, not libsignal wire-compatible beyond XEdDSA vectors).

## Hard break

Persisted dual-key identities, pre-spec XEdDSA signatures, and handshake wire **v3** will not load or interoperate. **Regenerate identities, re-sign SPK/PQ prekeys, and re-pair sessions** after upgrading `signal-protocol-core`, `pqxdh-core`, and `crypto-cascade`. Wire version is **4**.

## Findings (mitigation status)

| ID | Severity | Status | Fix summary | Regression |
| --- | --- | --- | --- | --- |
| SP-2026-001 | High | **Mitigated** | Skip/archive old chain up to `PN` before DH ratchet | `sp_2026_001_previous_chain_delayed_message_recovers` |
| SP-2026-002 | High | **Mitigated** | Decrypt on tentative state; commit only after AEAD | `sp_2026_002_forged_ratchet_key_does_not_desync` |
| SP-2026-003 | High | **Mitigated** | Skipped-key delete only after AEAD success | `sp_2026_003_forged_skipped_key_preserves_real_message` |
| SP-2026-004 | High | **Mitigated** | `x3dh_initiate_internal` verifies SPK; WASM exports verify/sign | unit + initiate failure tests |
| SP-2026-005 | Medium | **Mitigated** | AD = `IK_A \|\| IK_B`; threaded into ratchet AEAD | X3DH / DR unit tests |
| SP-2026-006 | Medium | **Mitigated** | XEdDSA on identity (`xeddsa.rs`); hard break | `xeddsa_*`, `sign_prekey_with_identity_xeddsa` |
| SP-2026-007 | Medium | **Mitigated** | Initiator first chain via DH with remote SPK; responder seeds SPK | role init tests |
| SP-2026-008 | Medium/Low | **Mitigated** | `max_skipped_total` + FIFO eviction | `cleanup_skipped_message_keys_fifo` |
| SP-2026-009 | Low | **Mitigated** | Overflow check before `+= 1` | encrypt path |
| SP-2026-010 | Medium | **Mitigated** | Reject all-zero X25519 shared secrets | `crypto` ECDH path |
| SP-2026-011 | High | **Mitigated** | WASM `EncryptionResult` no longer exposes `message_key` | WASM types |
| SP-2026-012 | High | **Mitigated** | Removed insecure init APIs; typed `RatchetRole` / `PqxdhRole` only | empty-AD / wrong-length init tests |
| SP-2026-013 | High | **Mitigated** | XEdDSA rewritten to Signal spec; `xeddsa-interop` + vectors | interop + canonical-`s` negatives |
| SP-2026-014 | Medium | **Mitigated** | Signal handshake `one_time_prekey_id` (wire v4); lookup-by-id consume | cascade OTPK id / replay tests |
| SP-2026-015 | Medium | **Mitigated** | `decrypt_from_peer` / group path clone-commit after AEAD | forged-first-message identity tests |
| SP-2026-016 | Medium | **Mitigated** | Removed legacy WASM `encrypt_message` / `decrypt_message` | WASM surface / Jest |
| SP-2026-017 | Low | **Mitigated** | `ensure_signed_prekeys` covers Signal + PQXDH SPK/PQ; api secrets load | cascade refresh + api `local_secrets` |

## Formal verification

ProVerif models under `formal-proofs/proverif/` (including `sp2026_hardening.pv`) encode:

- single identity key for DH + sign
- initiator SPK signature check before derive
- AEAD AD = `IK_A || IK_B`
- state-advance only after successful AEAD
- OTPK used at most once (`inj-event` correspondence)

hax F\*/Rocq/Lean extracts were re-run for `signal-protocol-core` and `pqxdh-core` after the init API rename. Rocq verify passes; treat remaining F\* SMT gaps as orthogonal to this hardening claim.

## Appendix A — Traceability (post-fix)

| Finding | Code | Test | Allium |
| --- | --- | --- | --- |
| 001–003, 008–009 | `double_ratchet.rs` | `audit_probes.rs`, DR unit tests | `DecryptCommitsOnlyAfterTag`, `SkippedKeysAreBounded` |
| 004–005 | `x3dh.rs`, DR AAD | X3DH unit tests | `SignedPrekeyVerifiedInInitiate`, `AssociatedDataBindsIdentities` |
| 006, 013 | `xeddsa.rs`, `keys.rs` | XEdDSA + interop | `XEdDSACanonical` |
| 007, 012 | `initialize_double_ratchet` + `RatchetRole` | initiator/responder / empty-AD | `InitRequiresSpkAndAd` |
| 010 | `crypto.rs` `x25519_ecdh` | crypto tests | — |
| 011, 016 | WASM surface | Jest / structure tests | `MessageKeyNotExported` |
| 014–015, 017 | `crypto-cascade` product/group | cascade product tests | `OneTimePreKeysBelongToOneSession`, `ProductDecryptCommitsAfterAuth` |

## Appendix B — How to verify

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo test -p signal-protocol-core --test audit_probes
cargo test -p signal-protocol-core
cargo test --manifest-path xeddsa-interop/Cargo.toml
cd formal-proofs && ./test_proverif.sh
# cascade (from crypto repo):
npm run test:rust:coverage:cascade
```

All former defect probes are inverted to positive regressions and must pass.
