# SP-2026 — signal-protocol library security review

| Field | Value |
| --- | --- |
| Date | 27 October 2026 |
| Subject | `signal-protocol-core` (X3DH + Double Ratchet) and WASM bindings in this repository |
| Method | Static review against Signal X3DH / Double Ratchet specifications; runtime probes that document current defects |
| Status | In-house research review — **not** an independent firm audit |
| Not claimed | Safety of the Glitr messenger; anonymity; Signal-app wire compatibility; that ProVerif/hax jobs cover these findings |

Related artefacts:

- Runtime probes: [`signal-protocol-core/tests/audit_probes.rs`](../signal-protocol-core/tests/audit_probes.rs)
- Behavioural specs (Allium): [`specs/`](../specs/)
- Formal verification notes: [`formal-proofs/docs/FORMAL_PROOF_STATUS.md`](../formal-proofs/docs/FORMAL_PROOF_STATUS.md)
- Public docs: [Behavioural specs](https://positive-intentions.com/docs/technical/formal-verification/behavioural-specs) (site PR paired with this review)

## Executive summary

This library is **not safe for production messaging** until at least **SP-2026-001**, **SP-2026-002**, and **SP-2026-003** are fixed. A single forged or delayed Double Ratchet ciphertext can permanently desynchronise a session. Signed-prekey authentication is not enforced inside X3DH (**SP-2026-004**). Formal models and existing unit tests do not encode authenticate-before-mutate or previous-chain recovery via `PN`.

Green CI on ProVerif or hax stub type-checks does **not** contradict these findings.

## Methodology

1. Inventory public core API vs WASM exports.
2. Diff decrypt / X3DH control flow against [Signal Double Ratchet](https://signal.org/docs/specifications/doubleratchet/) §2.6, §3.1–§3.5 and [X3DH](https://signal.org/docs/specifications/x3dh/) §2.2–§3.3.
3. Confirm High/Critical items with dual evidence: path:line **and** a named probe under `audit_probes.rs`.
4. Classify tip/Allium feedback as Protocol defect / API footgun / Variant / Open design / Partial / Rejected.
5. Second-pass adversarial re-check of each High/Critical (see [Traceability matrix](#appendix-a--traceability-matrix)).

Severity (aligned with the Glitr in-house review vocabulary):

| Severity | Used when |
| --- | --- |
| **Critical** | Long-term keys exposed to JS/network, or equivalent |
| **High** | Session integrity / availability breakable by one network message; handshake auth optional |
| **Medium** | Missing bound or control that enables DoS or weakens a layer without immediate key theft |
| **Low** | Hygiene, overflow edge, cleanup policy |
| **Info** | Intentional variant or positive control |

**Confirmed** means code and (for High+) probes were exercised on this tree on the report date.

## Findings

### SP-2026-001 — Late previous-chain message breaks the session (P1)

| | |
| --- | --- |
| Severity | **High** |
| Class | Protocol defect |
| Status | Confirmed |
| Spec | Double Ratchet §2.6 (out-of-order / `PN`), §3.4 `RatchetDecrypt` / `SkipMessageKeys` on DH step |
| Static | [`double_ratchet.rs`](../signal-protocol-core/src/double_ratchet.rs) `double_ratchet_decrypt_internal`: DH ratchet if `receiving_dh_public_key != message.dh_public_key`; `previous_chain_length` used only in AEAD AAD, never to archive old-chain keys before replacing `receiving_chain_key` |
| Probe | `sp_2026_001_documents_late_previous_chain_message_breaks_session`, `sp_2026_001b_documents_pn_ignored_on_dh_ratchet` |

**Impact.** After a normal DH ratchet, a delayed ciphertext from the prior sending chain is treated as a new remote ratchet key. State advances; AEAD fails or keys disagree; subsequent honest messages fail. Signal’s design stores remaining old-chain keys using header `PN` before installing the new remote DH key.

**Remediation direction.** On DH step: skip/archive keys on the current receiving chain up to `message.previous_chain_length`, then ratchet; try skipped keys keyed by `(dh, n)` without spuriously ratcheting when the key is already in `MKSKIPPED`. Prefer decrypt-on-copy / commit-after-AEAD (also SP-2026-002/003).

---

### SP-2026-002 — Forged ratchet public key desynchronises the session (P2)

| | |
| --- | --- |
| Severity | **High** |
| Class | Protocol defect |
| Status | Confirmed |
| Spec | Double Ratchet §3.1 `DECRYPT` “authentication fails → terminate”; production practice is not to commit ratchet/skip side effects on AEAD failure |
| Static | `perform_dh_ratchet_step` then `skip_message_keys` then `aead_decrypt`; no snapshot/rollback on `Err` |
| Probe | `sp_2026_002_documents_forged_ratchet_key_desyncs_session` |

**Impact.** One attacker message with a fresh 32-byte `dh_public_key` and garbage ciphertext changes Bob’s root/chain keys. The next honest Alice message fails. This is an unauthenticated state-mutation / DoS against the session.

**Note.** The published DR pseudocode also orders DH ratchet before `DECRYPT` on the new chain; production libsignal restores or copies state. Treat “paper vs production” carefully — the **availability** break is still Confirmed here.

**Remediation direction.** Decrypt against a tentative state (or restore on AEAD failure). Reject low-order / invalid DH public keys early (related: SP-2026-010).

---

### SP-2026-003 — Forged skipped-key header deletes the stored key (P3)

| | |
| --- | --- |
| Severity | **High** |
| Class | Protocol defect |
| Status | Confirmed |
| Spec | Intent: skipped keys survive until a **successful** decrypt (production); paper `TrySkippedMessageKeys` deletes before `DECRYPT` |
| Static | `skipped_message_keys.remove(&key_id)` before `aead_decrypt` |
| Probe | `sp_2026_003_documents_forged_skipped_key_delete_before_tag` |

**Impact.** After legitimate out-of-order skip, an adversary who can forge a header naming `(dh, n)` with wrong ciphertext burns the stored key. The real message then fails (`InvalidInput` / decrypt error).

**Remediation direction.** Look up skipped key, AEAD-verify, delete only on success (or restore on failure).

---

### SP-2026-004 — Signed prekey signature never checked in X3DH

| | |
| --- | --- |
| Severity | **High** |
| Class | API footgun / protocol gap at library boundary |
| Status | Confirmed |
| Spec | X3DH §3.2.3 — Alice verifies Bob’s SPK signature with Bob’s identity key (XEdDSA in Signal) |
| Static | [`x3dh_initiate_internal`](../signal-protocol-core/src/x3dh.rs) has no signature parameter; [`verify_signed_prekey`](../signal-protocol-core/src/keys.rs) exists in core but is **not** WASM-exported ([`src/rust/mod.rs`](../src/rust/mod.rs)) |
| Probe | `sp_2026_004_documents_verify_signed_prekey_unused_by_x3dh` |

**Impact.** Prekey authentication depends on every application remembering to verify. WASM/JS demos and gallery paths that call `x3dh_initiate` without a prior verify accept an unbound SPK.

**Remediation direction.** Take `(sign_public, signature)` into initiate (or a dedicated bundle type) and verify inside the library; export verify helpers from WASM; prefer XEdDSA on the identity key (SP-2026-006).

---

### SP-2026-005 — X3DH associated data is a constant string

| | |
| --- | --- |
| Severity | **Medium** |
| Class | Protocol defect (binding) / Partial vs tip feedback |
| Status | Confirmed (constant AD); **Partial** on “ratchet never uses AD” |
| Spec | X3DH §3.3 — AD typically identity key material; DR §3.1 — `CONCAT(AD, header)` into AEAD |
| Static | `associated_data = b"X3DH_Key_Exchange"`; DR AAD is `dh_public_key \|\| n \|\| pn` only — X3DH AD is not passed into `initialize_double_ratchet_internal` or seal/open |

**Impact.** Session AEAD does not bind the two long-term identities. Tip claim that the ratchet “never uses” associated data is **overstated**: header fields are authenticated; identity binding is what is missing.

**Remediation direction.** Set AD = `IK_A || IK_B` (or Signal’s Encode format) and feed into every seal/open; thread through ratchet init.

---

### SP-2026-006 — Identity key and signing key are unrelated (not XEdDSA)

| | |
| --- | --- |
| Severity | **Medium** |
| Class | Open design / variant from Signal |
| Status | Confirmed |
| Spec | X3DH uses XEdDSA on the X25519 identity key |
| Static | X25519 `generate_identity_keypair`; separate Ed25519 `generate_sign_keypair` |

**Impact.** Two long-term keys must be bound by application policy; no single-key identity.

---

### SP-2026-007 — Initiator first sending chain has no DH ratchet

| | |
| --- | --- |
| Severity | **Medium** |
| Class | Protocol defect vs Signal DR init |
| Status | Confirmed (initiator); Partial (responder first receive uses `perform_dh_ratchet_step`) |
| Spec | Double Ratchet §3.3 initialisation — Alice’s first sending chain typically from DH with Bob’s SPK / ratchet key |
| Static | Initiator: HKDF `Signal_Initial_Chain` over root only |

---

### SP-2026-008 — Skipped-key store unbounded across calls; cleanup is lexicographic

| | |
| --- | --- |
| Severity | **Medium** / **Low** (cleanup order) |
| Class | Protocol defect (bounds) / Low (eviction policy) |
| Status | Confirmed |
| Spec | DR §3.2 `MAX_SKIP`; implementations also bound total `MKSKIPPED` |
| Static | Per-call cap `MAX_SKIPPED_MESSAGE_KEYS = 1000` in `skip_message_keys`; map can grow across many DH chains; `cleanup_skipped_message_keys_internal` sorts string keys and is never called from decrypt |
| Probe | `sp_2026_008_documents_cleanup_lexicographic_not_oldest` |

---

### SP-2026-009 — Sending message counter is `u32` without overflow check

| | |
| --- | --- |
| Severity | **Low** |
| Class | Protocol defect (edge) |
| Status | Confirmed |
| Static | `sending_message_number += 1` with no check |

---

### SP-2026-010 — DH output not rejected for all-zero / small-order contributions

| | |
| --- | --- |
| Severity | **Medium** |
| Class | Protocol defect / crypto hygiene |
| Status | Confirmed |
| Spec | X25519 implementations should reject low-order public keys / all-zero shared secrets where required |
| Static | [`x25519_ecdh`](../signal-protocol-core/src/crypto.rs) returns `diffie_hellman` bytes with length checks only |

---

### SP-2026-011 — Legacy `encrypt_message` returns `message_key` to JavaScript

| | |
| --- | --- |
| Severity | **High** (secret export) |
| Class | API footgun |
| Status | Confirmed |
| Static | [`EncryptionResult.message_key`](../src/rust/types.rs) WASM getter; [`encrypt_message_internal`](../src/rust/messages.rs) |

**Impact.** Any page script or extension that can read the WASM return value learns the message key. Not needed for decrypt (caller already has the shared secret path).

**Remediation direction.** Stop exporting `message_key`; decrypt should take ciphertext + derived context only inside Rust.

---

## Variants (not defects)

| Item | Notes |
| --- | --- |
| Non-standard HKDF salts / info strings | Both peers agree (`Signal_X3DH_Salt`, `Signal_DoubleRatchet_*`, etc.). Documented in `formal-proofs/docs/HKDF_CONSTANTS.md`. Class: **Variant**. |

## Formal verification gap (honest)

ProVerif models under `formal-proofs/proverif/` encode idealized DR/X3DH flows and AAD *layout* matching the implementation. They do **not** model:

- Commit-after-AEAD / rollback
- `PN`-driven old-chain skip
- Mandatory SPK signature verify inside initiate

Therefore a green ProVerif job is **orthogonal** to SP-2026-001–004. See also site page [Signal Protocol formal verification](https://positive-intentions.com/docs/technical/formal-verification/signal-protocol) and [Behavioural specs](https://positive-intentions.com/docs/technical/formal-verification/behavioural-specs).

## Recommended fix order

1. Authenticate before mutate (SP-2026-002, SP-2026-003) — tentative state or restore on AEAD failure  
2. Honour `PN` / previous-chain skipped keys (SP-2026-001)  
3. Bind SPK verify into X3DH + export from WASM (SP-2026-004); stop exporting `message_key` (SP-2026-011)  
4. Identity-bound AD into every seal/open (SP-2026-005)  
5. Bounds on total skipped keys; safer cleanup (SP-2026-008); DH contributory checks (SP-2026-010); counter overflow (SP-2026-009)  
6. Design pass on XEdDSA / first-chain DH (SP-2026-006, SP-2026-007)

Do **not** invert audit probes until the corresponding finding is fixed; then replace with positive regression tests.

## Appendix A — Traceability matrix

| Finding | Severity | Static cite | Probe | Spec | Allium invariant | FV gap | Second-pass |
| --- | --- | --- | --- | --- | --- | --- | --- |
| SP-2026-001 | High | `double_ratchet.rs` decrypt / PN unused for skip | `sp_2026_001*`, `sp_2026_001b*` | DR §2.6, §3.4 | `PreviousChainKeysRetainedOnRatchet` | absent | **Confirmed** (001b is the cleanest PN case) |
| SP-2026-002 | High | ratchet+skip before AEAD | `sp_2026_002*` | DR §3.1 intent / production | `DecryptCommitsOnlyAfterTag` | absent | **Confirmed** (root changes on forge) |
| SP-2026-003 | High | `remove` before AEAD | `sp_2026_003*` | production skipped-key lifetime | `SkippedKeyRemovedOnlyAfterTag` | absent | **Confirmed** |
| SP-2026-004 | High | `x3dh.rs` / WASM exports | `sp_2026_004*` | X3DH §3.2.3 | `SignedPrekeyVerifiedInInitiate` | absent | **Confirmed** |
| SP-2026-005 | Medium | constant AD; DR header AAD only | static | X3DH §3.3, DR CONCAT | `AssociatedDataBindsIdentities` | partial AAD modeled | **Partial** tip wording |
| SP-2026-006 | Medium | `keys.rs` | static | XEdDSA | open question | n/a | **Confirmed** as design gap |
| SP-2026-007 | Medium | initiator init HKDF | static | DR §3.3 | open question | n/a | **Confirmed** initiator |
| SP-2026-008 | Medium/Low | max skip / cleanup | `sp_2026_008*` | DR MAX_SKIP | `SkippedKeysAreBounded` | absent | **Confirmed** |
| SP-2026-009 | Low | `+= 1` | static | — | — | n/a | **Confirmed** |
| SP-2026-010 | Medium | `x25519_ecdh` | static | X25519 contributory | — | n/a | **Confirmed** |
| SP-2026-011 | High | WASM `message_key` | static + type | — | `MessageKeyNotExported` | n/a | **Confirmed** |

### Second-pass notes

- Re-checked P1: same-chain OOO tests only cover intra-chain skip; **001b** is the decisive PN-ignorance case.  
- Re-checked “ratchet never uses AD”: **Rejected as absolute**; narrowed to identity-binding gap (SP-2026-005).  
- Paper vs production on skipped-key delete: finding kept because this tree matches the unsafe paper order and probes show loss of the real message.

## Appendix B — How to reproduce

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo test -p signal-protocol-core --test audit_probes
```

All probes must pass on an unfixed tree (they assert broken behaviour).
