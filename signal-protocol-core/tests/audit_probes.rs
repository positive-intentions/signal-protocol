//! Regression probes for SP-2026 remediations (formerly defect-documenting tests).

#![cfg(feature = "crypto-backend")]

use signal_protocol_core::{
    double_ratchet_decrypt_internal, double_ratchet_encrypt_internal, generate_identity_keypair,
    test_ratchet_pair, DoubleRatchetMessage, SignalError,
};

fn shared_secret() -> [u8; 32] {
    [0x11u8; 32]
}

fn ad() -> &'static [u8] {
    b"audit_probe_ad_IK_A||IK_B______"
}

fn pair() -> (
    signal_protocol_core::DoubleRatchetState,
    signal_protocol_core::DoubleRatchetState,
) {
    let (alice, bob, _) = test_ratchet_pair(&shared_secret(), ad()).unwrap();
    (alice, bob)
}

/// SP-2026-001 — delayed previous-chain message decrypts via PN-archived keys.
#[test]
fn sp_2026_001_previous_chain_delayed_message_recovers() {
    let (mut alice, mut bob) = pair();

    let m0 = double_ratchet_encrypt_internal(&mut alice, b"a0").unwrap();
    let m1_delayed = double_ratchet_encrypt_internal(&mut alice, b"a1").unwrap();

    assert_eq!(
        double_ratchet_decrypt_internal(&mut bob, &m0).unwrap(),
        b"a0"
    );

    let bob_reply = double_ratchet_encrypt_internal(&mut bob, b"b0").unwrap();
    double_ratchet_decrypt_internal(&mut alice, &bob_reply).unwrap();

    let m2 = double_ratchet_encrypt_internal(&mut alice, b"a2-new-chain").unwrap();
    assert_ne!(m2.dh_public_key, m0.dh_public_key);
    assert_eq!(m2.previous_chain_length, 2);
    assert_eq!(
        double_ratchet_decrypt_internal(&mut bob, &m2).unwrap(),
        b"a2-new-chain"
    );

    assert_eq!(
        double_ratchet_decrypt_internal(&mut bob, &m1_delayed).unwrap(),
        b"a1"
    );

    let m3 = double_ratchet_encrypt_internal(&mut alice, b"a3").unwrap();
    assert_eq!(
        double_ratchet_decrypt_internal(&mut bob, &m3).unwrap(),
        b"a3"
    );
}

/// SP-2026-002 — forged ratchet key does not desync the session.
#[test]
fn sp_2026_002_forged_ratchet_key_does_not_desync() {
    let (mut alice, mut bob) = pair();

    let m0 = double_ratchet_encrypt_internal(&mut alice, b"hello").unwrap();
    assert_eq!(
        double_ratchet_decrypt_internal(&mut bob, &m0).unwrap(),
        b"hello"
    );

    let root_before = bob.root_key.clone();
    let forged = DoubleRatchetMessage {
        ciphertext: vec![0u8; 40],
        dh_public_key: generate_identity_keypair().public_key,
        message_number: 0,
        previous_chain_length: 0,
    };

    let err = double_ratchet_decrypt_internal(&mut bob, &forged).unwrap_err();
    assert!(matches!(err, SignalError::Decryption(_)));
    assert_eq!(bob.root_key, root_before);

    let honest = double_ratchet_encrypt_internal(&mut alice, b"still friends?").unwrap();
    assert_eq!(
        double_ratchet_decrypt_internal(&mut bob, &honest).unwrap(),
        b"still friends?"
    );
}

/// SP-2026-003 — forged skipped-key header does not burn the real key.
#[test]
fn sp_2026_003_forged_skipped_key_preserves_real_message() {
    let (mut alice, mut bob) = pair();

    let m0 = double_ratchet_encrypt_internal(&mut alice, b"m0").unwrap();
    let _m1 = double_ratchet_encrypt_internal(&mut alice, b"m1").unwrap();
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
        bob.skipped_message_keys.contains_key(&key_id),
        "skipped key must survive failed forged decrypt"
    );

    assert_eq!(
        double_ratchet_decrypt_internal(&mut bob, &m0).unwrap(),
        b"m0"
    );
}
