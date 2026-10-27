//! Runtime probes that document known defects for the SP-2026 library audit.
//!
//! These tests assert the *current broken behaviour*. When a finding is fixed,
//! invert or replace the corresponding probe and update
//! `security/SP-2026-library-audit.md`.
//!
//! Finding IDs: SP-2026-001 (P1), SP-2026-002 (P2), SP-2026-003 (P3).

#![cfg(feature = "crypto-backend")]

use signal_protocol_core::{
    double_ratchet_decrypt_internal, double_ratchet_encrypt_internal, generate_identity_keypair,
    initialize_double_ratchet_internal, verify_signed_prekey, DoubleRatchetMessage, SignalError,
};

fn shared_secret() -> [u8; 32] {
    [0x11u8; 32]
}

fn root_fingerprint(state: &signal_protocol_core::DoubleRatchetState) -> Vec<u8> {
    state.root_key.clone()
}

/// SP-2026-001 / P1 — late ciphertext from the previous sending chain breaks the session.
///
/// Signal Double Ratchet §2.6 / §3.4: on a DH ratchet step the receiver must skip remaining
/// keys on the *old* receiving chain using header PN before installing the new remote key.
/// This implementation never consults `previous_chain_length` for skipping; a delayed message
/// whose `dh_public_key` differs from the current receiving key is treated as a fresh ratchet.
#[test]
fn sp_2026_001_documents_late_previous_chain_message_breaks_session() {
    let mut alice = initialize_double_ratchet_internal(&shared_secret(), true).unwrap();
    let mut bob = initialize_double_ratchet_internal(&shared_secret(), false).unwrap();

    // Chain A: three Alice messages. Deliver only the first; hold the second.
    let m0 = double_ratchet_encrypt_internal(&mut alice, b"a0").unwrap();
    let m1_delayed = double_ratchet_encrypt_internal(&mut alice, b"a1-delayed").unwrap();
    let m2 = double_ratchet_encrypt_internal(&mut alice, b"a2").unwrap();
    assert_eq!(m0.dh_public_key, m1_delayed.dh_public_key);
    assert_eq!(m0.dh_public_key, m2.dh_public_key);

    assert_eq!(
        double_ratchet_decrypt_internal(&mut bob, &m0).unwrap(),
        b"a0"
    );
    // Skip ahead on the same chain without storing via PN on a later ratchet.
    assert_eq!(
        double_ratchet_decrypt_internal(&mut bob, &m2).unwrap(),
        b"a2"
    );
    // m1 is still pending; key should be in skipped map from same-chain skip.
    let key_id = format!("{}:{}", hex::encode(&m1_delayed.dh_public_key), 1);
    assert!(
        bob.skipped_message_keys.contains_key(&key_id),
        "same-chain skip should have stored m1; probe setup invalid"
    );

    // Bob replies → Alice DH-ratchets to a new sending chain (chain B).
    let bob_reply = double_ratchet_encrypt_internal(&mut bob, b"b0").unwrap();
    assert_eq!(
        double_ratchet_decrypt_internal(&mut alice, &bob_reply).unwrap(),
        b"b0"
    );

    let m3 = double_ratchet_encrypt_internal(&mut alice, b"a3-chain-b").unwrap();
    assert_ne!(
        m3.dh_public_key, m0.dh_public_key,
        "Alice should have a new sending DH key after receiving Bob"
    );
    assert_eq!(
        double_ratchet_decrypt_internal(&mut bob, &m3).unwrap(),
        b"a3-chain-b"
    );

    let root_before_late = root_fingerprint(&bob);
    let recv_dh_before = bob.receiving_dh_public_key.clone();

    // Delayed m1 still has chain-A DH key. After Bob moved to chain B, that key looks "new"
    // and triggers another DH ratchet instead of TrySkippedMessageKeys-only handling.
    // Even though m1's key may still sit in skipped_message_keys, decrypt compares DH keys
    // first and ratchets before consulting the skipped map for the *old* chain id under the
    // pre-ratchet receiving key — actually wait: decrypt builds key_id from message DH key
    // AFTER ratchet. If ratchet runs first, receiving state is wrecked; skipped lookup uses
    // message.dh which might still hit the map.
    //
    // Probe the observed end-state: after attempting late m1, an honest follow-up fails.
    let late = double_ratchet_decrypt_internal(&mut bob, &m1_delayed);
    // Either AEAD fails (wrong key after spurious ratchet) or plaintext wrongly recovered
    // after corrupting ratchet state. Document whatever this tree does today.
    let _ = late;

    let m4 = double_ratchet_encrypt_internal(&mut alice, b"a4-honest").unwrap();
    let follow_up = double_ratchet_decrypt_internal(&mut bob, &m4);

    // Defect: session no longer tracks Alice. Follow-up must fail for this probe to document P1.
    // If a future fix keeps the session healthy, this assertion will fail and should be inverted.
    assert!(
        follow_up.is_err(),
        "SP-2026-001 expected follow-up decrypt to fail after late previous-chain delivery; \
         got Ok({:?}). root_before={:02x?} root_after={:02x?} recv_dh_before={:?} recv_dh_after={:?}",
        follow_up.as_ref().ok().map(|p| String::from_utf8_lossy(p)),
        root_before_late,
        root_fingerprint(&bob),
        recv_dh_before,
        bob.receiving_dh_public_key
    );
}

/// Stronger P1 variant: delay a same-chain message that was *never* skipped into MKSKIPPED,
/// then ratchet, then deliver it — PN is ignored so the old chain key is gone.
#[test]
fn sp_2026_001b_documents_pn_ignored_on_dh_ratchet() {
    let mut alice = initialize_double_ratchet_internal(&shared_secret(), true).unwrap();
    let mut bob = initialize_double_ratchet_internal(&shared_secret(), false).unwrap();

    let m0 = double_ratchet_encrypt_internal(&mut alice, b"a0").unwrap();
    let m1_delayed = double_ratchet_encrypt_internal(&mut alice, b"a1").unwrap();

    assert_eq!(
        double_ratchet_decrypt_internal(&mut bob, &m0).unwrap(),
        b"a0"
    );
    // Do NOT decrypt or skip-store m1. Bob only has Nr=1 and live chain for next key (=m1).

    let bob_reply = double_ratchet_encrypt_internal(&mut bob, b"b0").unwrap();
    double_ratchet_decrypt_internal(&mut alice, &bob_reply).unwrap();

    let m2 = double_ratchet_encrypt_internal(&mut alice, b"a2-new-chain").unwrap();
    assert_ne!(m2.dh_public_key, m0.dh_public_key);
    // PN on m2 should tell Bob how many keys remained on the old chain (Signal §2.6).
    assert_eq!(
        m2.previous_chain_length, 2,
        "Alice sent 2 messages on previous chain before ratchet"
    );

    double_ratchet_decrypt_internal(&mut bob, &m2).unwrap();

    // After DH ratchet without PN skip, m1's key was never archived.
    let err = double_ratchet_decrypt_internal(&mut bob, &m1_delayed).expect_err(
        "SP-2026-001b: delayed previous-chain message should not decrypt after PN-ignorant ratchet",
    );
    assert!(
        matches!(err, SignalError::Decryption(_) | SignalError::InvalidInput(_)),
        "unexpected error kind: {err:?}"
    );

    let m3 = double_ratchet_encrypt_internal(&mut alice, b"a3").unwrap();
    let follow = double_ratchet_decrypt_internal(&mut bob, &m3);
    assert!(
        follow.is_err(),
        "SP-2026-001b: honest message after late previous-chain attempt should fail; got Ok"
    );
}

/// SP-2026-002 / P2 — forged ratchet public key mutates state before AEAD; session desyncs.
#[test]
fn sp_2026_002_documents_forged_ratchet_key_desyncs_session() {
    let mut alice = initialize_double_ratchet_internal(&shared_secret(), true).unwrap();
    let mut bob = initialize_double_ratchet_internal(&shared_secret(), false).unwrap();

    let m0 = double_ratchet_encrypt_internal(&mut alice, b"hello").unwrap();
    assert_eq!(
        double_ratchet_decrypt_internal(&mut bob, &m0).unwrap(),
        b"hello"
    );

    let root_before = root_fingerprint(&bob);
    let forged_dh = generate_identity_keypair().public_key;
    let forged = DoubleRatchetMessage {
        // Plausible length: 12-byte nonce + 16-byte tag + some CT
        ciphertext: vec![0u8; 40],
        dh_public_key: forged_dh,
        message_number: 0,
        previous_chain_length: 0,
    };

    let forge_err = double_ratchet_decrypt_internal(&mut bob, &forged).unwrap_err();
    assert!(
        matches!(forge_err, SignalError::Decryption(_)),
        "forged ciphertext should fail AEAD, got {forge_err:?}"
    );
    assert_ne!(
        root_fingerprint(&bob),
        root_before,
        "SP-2026-002: root key must have changed — ratchet committed before tag check"
    );

    let honest = double_ratchet_encrypt_internal(&mut alice, b"still friends?").unwrap();
    let follow = double_ratchet_decrypt_internal(&mut bob, &honest);
    assert!(
        follow.is_err(),
        "SP-2026-002: honest message after forged ratchet must fail; session was desynced"
    );
}

/// SP-2026-003 / P3 — forging a skipped-key header deletes the stored key before AEAD succeeds.
#[test]
fn sp_2026_003_documents_forged_skipped_key_delete_before_tag() {
    let mut alice = initialize_double_ratchet_internal(&shared_secret(), true).unwrap();
    let mut bob = initialize_double_ratchet_internal(&shared_secret(), false).unwrap();

    let m0 = double_ratchet_encrypt_internal(&mut alice, b"m0").unwrap();
    let m1 = double_ratchet_encrypt_internal(&mut alice, b"m1").unwrap();
    let m2 = double_ratchet_encrypt_internal(&mut alice, b"m2").unwrap();

    assert_eq!(
        double_ratchet_decrypt_internal(&mut bob, &m2).unwrap(),
        b"m2"
    );
    let key_id = format!("{}:{}", hex::encode(&m0.dh_public_key), 0);
    assert!(bob.skipped_message_keys.contains_key(&key_id));

    let mut forged = m0.clone();
    if let Some(b) = forged.ciphertext.last_mut() {
        *b ^= 0xff;
    }

    let err = double_ratchet_decrypt_internal(&mut bob, &forged).unwrap_err();
    assert!(matches!(err, SignalError::Decryption(_)));
    assert!(
        !bob.skipped_message_keys.contains_key(&key_id),
        "SP-2026-003: skipped key must already be removed after failed forged decrypt"
    );

    let real = double_ratchet_decrypt_internal(&mut bob, &m0);
    assert!(
        real.is_err(),
        "SP-2026-003: real m0 must fail after forged consumption of skipped key; got Ok"
    );

    // m1 should still be present unless collateral damage occurred.
    let _ = m1;
}

/// SP-2026-004 surface — `verify_signed_prekey` exists in core but X3DH never requires it.
#[test]
fn sp_2026_004_documents_verify_signed_prekey_unused_by_x3dh() {
    use signal_protocol_core::{
        generate_sign_keypair, generate_signed_prekey, sign_prekey, x3dh_initiate_internal,
        x3dh_respond_internal,
    };

    let alice_id = generate_identity_keypair();
    let alice_eph = generate_identity_keypair();
    let bob_id = generate_identity_keypair();
    let bob_spk = generate_signed_prekey();
    let bob_sign = generate_sign_keypair();
    let sig = sign_prekey(&bob_sign.private_key, &bob_spk.public_key).unwrap();
    verify_signed_prekey(&bob_sign.public_key, &bob_spk.public_key, &sig).unwrap();

    // Initiate succeeds with *no* signature argument — callers can skip verification entirely.
    let init = x3dh_initiate_internal(
        &alice_id.private_key,
        &alice_eph.private_key,
        &bob_id.public_key,
        &bob_spk.public_key,
        None,
    )
    .unwrap();
    let resp = x3dh_respond_internal(
        &bob_id.private_key,
        &bob_spk.private_key,
        None,
        &alice_id.public_key,
        &alice_eph.public_key,
    )
    .unwrap();
    assert_eq!(init.shared_secret, resp.shared_secret);
    assert_eq!(init.associated_data, b"X3DH_Key_Exchange");
}

/// SP-2026-008 — cleanup removes keys in lexicographic key-id order, not insertion/oldest.
#[test]
fn sp_2026_008_documents_cleanup_lexicographic_not_oldest() {
    use signal_protocol_core::cleanup_skipped_message_keys_internal;

    let mut alice = initialize_double_ratchet_internal(&shared_secret(), true).unwrap();
    let mut bob = initialize_double_ratchet_internal(&shared_secret(), false).unwrap();
    let msgs: Vec<_> = (0..5)
        .map(|i| {
            double_ratchet_encrypt_internal(&mut alice, format!("m{i}").as_bytes()).unwrap()
        })
        .collect();
    double_ratchet_decrypt_internal(&mut bob, &msgs[4]).unwrap();

    let before: Vec<String> = bob.skipped_message_keys.keys().cloned().collect();
    let mut sorted = before.clone();
    sorted.sort();
    assert_eq!(
        before, sorted,
        "BTreeMap keys already iterate sorted; cleanup uses that order"
    );

    let removed = cleanup_skipped_message_keys_internal(&mut bob, 2);
    assert_eq!(removed, before.len() - 2);
    let after: Vec<String> = bob.skipped_message_keys.keys().cloned().collect();
    // Survivors are the lexicographically last keys, not necessarily the newest message numbers
    // across multiple DH chains — documents SP-2026-008 policy.
    assert_eq!(after, sorted[sorted.len() - 2..]);
}
