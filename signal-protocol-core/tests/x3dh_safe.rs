//! Integration test for the safe X3DH initiator path (`x3dh_initiate`).
//!
//! Covers:
//!  1. Honest initiate/respond round-trip - both parties derive the same SK.
//!  2. Tampered SPK signature - `x3dh_initiate` returns
//!     `SignalError::SignatureVerification` and never derives a shared
//!     secret.
//!  3. Wrong identity key (signature was made under a different IK) -
//!     same rejection path.
//!
//! This is the Rust counterpart of the ProVerif `signal_complete.pv`
//! property `attacker(secret_message) is true`: an attacker who
//! substitutes Bob's bundle on the wire is rejected before any SK is
//! computed.

use signal_protocol_core::{
    generate_ephemeral_keypair, generate_identity_keypair, generate_one_time_prekey,
    generate_signed_prekey, sign_data_internal, x3dh_initiate, x3dh_respond_internal,
    SignalError,
};

#[test]
fn x3dh_initiate_succeeds_and_agrees_with_responder() {
    let alice_id  = generate_identity_keypair();
    let alice_ek  = generate_ephemeral_keypair();
    let bob_id    = generate_identity_keypair();
    let bob_spk   = generate_signed_prekey();
    let bob_opk   = generate_one_time_prekey();

    let bob_spk_sig =
        sign_data_internal(bob_id.ed25519_private(), &bob_spk.public_key).expect("sign spk");

    let alice_result = x3dh_initiate(
        alice_id.x25519_private(),
        alice_id.x25519_public(),
        &alice_ek.private_key,
        bob_id.x25519_public(),
        bob_id.ed25519_public(),
        &bob_spk.public_key,
        &bob_spk_sig,
        Some(&bob_opk.public_key),
    )
    .expect("alice safe x3dh_initiate must succeed under honest bundle");

    let bob_result = x3dh_respond_internal(
        bob_id.x25519_private(),
        bob_id.x25519_public(),
        &bob_spk.private_key,
        Some(&bob_opk.private_key),
        alice_id.x25519_public(),
        &alice_ek.public_key,
    )
    .expect("bob x3dh_respond_internal must succeed");

    assert_eq!(
        alice_result.shared_secret, bob_result.shared_secret,
        "initiator and responder must agree on SK"
    );
    assert_eq!(alice_result.shared_secret.len(), 32);
    // Whitepaper-faithful AAD: IK_a || IK_b, both 32 bytes => 64 bytes.
    let mut expected_aad = Vec::with_capacity(64);
    expected_aad.extend_from_slice(alice_id.x25519_public());
    expected_aad.extend_from_slice(bob_id.x25519_public());
    assert_eq!(alice_result.associated_data, expected_aad);
    assert_eq!(bob_result.associated_data, expected_aad);
}

#[test]
fn x3dh_initiate_rejects_tampered_spk_signature() {
    let alice_id = generate_identity_keypair();
    let alice_ek = generate_ephemeral_keypair();
    let bob_id   = generate_identity_keypair();
    let bob_spk  = generate_signed_prekey();

    let mut bob_spk_sig =
        sign_data_internal(bob_id.ed25519_private(), &bob_spk.public_key).expect("sign spk");
    bob_spk_sig[0] ^= 0xFF;

    let err = x3dh_initiate(
        alice_id.x25519_private(),
        alice_id.x25519_public(),
        &alice_ek.private_key,
        bob_id.x25519_public(),
        bob_id.ed25519_public(),
        &bob_spk.public_key,
        &bob_spk_sig,
        None,
    )
    .expect_err("a tampered SPK signature must be rejected");

    assert!(
        matches!(err, SignalError::SignatureVerification(_)),
        "expected SignatureVerification, got {err:?}"
    );
}

#[test]
fn x3dh_initiate_rejects_wrong_signer_identity() {
    let alice_id   = generate_identity_keypair();
    let alice_ek   = generate_ephemeral_keypair();
    let bob_id     = generate_identity_keypair();
    let bob_spk    = generate_signed_prekey();
    let mallory_id = generate_identity_keypair();

    let mallory_spk_sig =
        sign_data_internal(mallory_id.ed25519_private(), &bob_spk.public_key).expect("sign");

    let err = x3dh_initiate(
        alice_id.x25519_private(),
        alice_id.x25519_public(),
        &alice_ek.private_key,
        bob_id.x25519_public(),
        bob_id.ed25519_public(),
        &bob_spk.public_key,
        &mallory_spk_sig,
        None,
    )
    .expect_err("an SPK signed by the wrong identity must be rejected");

    assert!(
        matches!(err, SignalError::SignatureVerification(_)),
        "expected SignatureVerification, got {err:?}"
    );
}
