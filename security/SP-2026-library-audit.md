# SP-2026 — signal-protocol library security review

| Field | Value |
| --- | --- |
| Date | 27 October 2026 |
| Subject | `signal-protocol-core` (X3DH + Double Ratchet) and WASM bindings in this repository |
| Method | Static review against Signal X3DH / Double Ratchet specifications; runtime probes |
| Status | Findings **Mitigated** in-tree (hard break: regenerate identities / re-pair). Still **not** an independent firm audit |
| Not claimed | Safety of the Glitr messenger; anonymity; Signal-app wire compatibility; that ProVerif/hax jobs cover these fixes |

Related artefacts:

- Positive regressions: [`signal-protocol-core/tests/audit_probes.rs`](../signal-protocol-core/tests/audit_probes.rs) (`sp_2026_001_fixed_*`, `sp_2026_002_fixed_*`, `sp_2026_003_fixed_*`)
- Behavioural specs (Allium): [`specs/`](../specs/)
- Formal verification notes: [`formal-proofs/docs/FORMAL_PROOF_STATUS.md`](../formal-proofs/docs/FORMAL_PROOF_STATUS.md)
- Consumers updated in the same delivery: `pqxdh-core`, `crypto-cascade` (identity hard break)
- Public docs: [Behavioural specs](https://positive-intentions.com/docs/technical/formal-verification/behavioural-specs)

## Executive summary

SP-2026-001–011 are **mitigated** in this repository:

- Double Ratchet: commit-after-AEAD, `PN` previous-chain skip, FIFO skipped-key bounds, counter overflow checks
- X3DH: SPK verify inside initiate; AD = `IK_A || IK_B` into every seal/open
- Identity: XEdDSA on a single X25519 key (**hard break** — no dual-key migration)
- Initiator first-chain DH against Bob’s SPK; all-zero DH rejected
- WASM: `verify_signed_prekey` / `sign_prekey` exported; `message_key` no longer exported

The library remains **research-grade** (not firm-audited, not libsignal wire-compatible). Green ProVerif/hax jobs still do not encode all of these controls.

## Hard break

Persisted dual-key identities (`signal_sign` / separate Ed25519) and old X3DH/ratchet wire assumptions will not load or interoperate. **Regenerate identities and re-pair sessions** after upgrading `signal-protocol-core`, `pqxdh-core`, and `crypto-cascade`.

## Findings (mitigation status)

| ID | Severity | Status | Fix summary | Regression |
| --- | --- | --- | --- | --- |
| SP-2026-001 | High | **Mitigated** | Skip/archive old chain up to `PN` before DH ratchet | `sp_2026_001_previous_chain_delayed_message_recovers` |
| SP-2026-002 | High | **Mitigated** | Decrypt on tentative state; commit only after AEAD | `sp_2026_002_forged_ratchet_key_does_not_desync` |
| SP-2026-003 | High | **Mitigated** | Skipped-key delete only after AEAD success | `sp_2026_003_forged_skipped_key_preserves_real_message` |
| SP-2026-004 | High | **Mitigated** | `x3dh_initiate_internal` verifies SPK; WASM exports verify/sign | unit + initiate failure tests |
| SP-2026-005 | Medium | **Mitigated** | AD = `IK_A \|\| IK_B`; threaded into ratchet AEAD | X3DH / DR unit tests |
| SP-2026-006 | Medium | **Mitigated** | XEdDSA on identity (`xeddsa.rs`); hard break | `xeddsa_*`, `sign_prekey_with_identity_xeddsa` |
| SP-2026-007 | Medium | **Mitigated** | Initiator first chain via DH with remote SPK; responder seeds SPK | `initiator_with_remote_spk_uses_dh_chain` |
| SP-2026-008 | Medium/Low | **Mitigated** | `max_skipped_total` + FIFO eviction | `cleanup_skipped_message_keys_fifo` |
| SP-2026-009 | Low | **Mitigated** | Overflow check before `+= 1` | encrypt path |
| SP-2026-010 | Medium | **Mitigated** | Reject all-zero X25519 shared secrets | `crypto` ECDH path |
| SP-2026-011 | High | **Mitigated** | WASM `EncryptionResult` no longer exposes `message_key` | WASM types |

## Formal verification gap (honest)

ProVerif models under `formal-proofs/proverif/` are **not** re-proved in this remediation to encode commit-after-AEAD / mandatory SPK verify. Treat model green as orthogonal until a follow-up updates the models.

## Appendix A — Traceability (post-fix)

| Finding | Code | Test | Allium |
| --- | --- | --- | --- |
| 001–003, 008–009 | `double_ratchet.rs` | `audit_probes.rs`, DR unit tests | invariants no longer `VIOLATED` |
| 004–005 | `x3dh.rs`, DR AAD | X3DH unit tests | `SignedPrekeyVerifiedInInitiate`, `AssociatedDataBindsIdentities` |
| 006 | `xeddsa.rs`, `keys.rs` | XEdDSA unit tests | open question resolved |
| 007 | `initialize_double_ratchet_full` | initiator/responder session tests | open question resolved |
| 010 | `crypto.rs` `x25519_ecdh` | crypto tests | — |
| 011 | WASM `messages.rs` / types | WASM surface | `MessageKeyNotExported` |

## Appendix B — How to verify

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo test -p signal-protocol-core --test audit_probes
cargo test -p signal-protocol-core
```

All former defect probes are inverted to positive regressions and must pass.
