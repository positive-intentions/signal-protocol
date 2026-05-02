//! X3DH (Extended Triple Diffie-Hellman) key agreement protocol
//!
//! Mirrors the algorithm in the Signal X3DH whitepaper version 1.0
//! (<https://signal.org/docs/specifications/x3dh/>) and the F* spec in
//! `proofs/fstar/spec/Spec.X3DH.fst`. The key schedule is:
//!
//! ```text
//!   DH1 = DH(IK_a,  SPK_b)
//!   DH2 = DH(EK_a,  IK_b)
//!   DH3 = DH(EK_a,  SPK_b)
//!   DH4 = DH(EK_a,  OPK_b)         (optional)
//!   SK  = HKDF(salt, F || DH1 || DH2 || DH3 [|| DH4], info, 32)
//! ```
//!
//! where `F = 0xFF^32` is the domain-separation prefix mandated by
//! whitepaper §3.3 step 3.

use crate::crypto::{hkdf_derive, simple_ecdh, verify_signature_internal, KEY_LEN};
use crate::error::SignalError;
use crate::types::X3DHResult;

/// `F = 0xFF^32` - the domain-separation prefix prepended to the DH
/// concatenation before HKDF, per X3DH §3.3 step 3.
pub const X3DH_F_PREFIX: [u8; 32] = [0xFFu8; 32];

pub(crate) const X3DH_SALT: &[u8] = b"Signal_X3DH_Salt";
pub(crate) const X3DH_INFO: &[u8] = b"Signal_X3DH_Key_Derivation";

/// Build the X3DH "associated data" per whitepaper §3.3 step 5:
/// `AD = ENCODE(IK_A_pub) || ENCODE(IK_B_pub)`.
///
/// The encoding is just byte-concatenation here (X25519 public keys
/// are length-fixed at 32 bytes so no length prefix is needed).
pub(crate) fn build_x3dh_aad(alice_ik_pub: &[u8], bob_ik_pub: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(alice_ik_pub.len() + bob_ik_pub.len());
    aad.extend_from_slice(alice_ik_pub);
    aad.extend_from_slice(bob_ik_pub);
    aad
}

#[hax_lib::include]
#[hax_lib::requires(
    alice_identity_private.len() == 32 &&
    alice_identity_public.len() == 32 &&
    alice_ephemeral_private.len() == 32 &&
    bob_identity_public.len() == 32 &&
    bob_signed_prekey_public.len() == 32
)]
#[hax_lib::ensures(|res| matches!(res, Ok(r) if r.shared_secret.len() == 32) || matches!(res, Err(_)))]
pub fn x3dh_initiate_internal(
    alice_identity_private: &[u8],
    alice_identity_public: &[u8],
    alice_ephemeral_private: &[u8],
    bob_identity_public: &[u8],
    bob_signed_prekey_public: &[u8],
    bob_one_time_prekey_public: Option<&[u8]>,
) -> Result<X3DHResult, SignalError> {
    let dh1 = simple_ecdh(alice_identity_private, bob_signed_prekey_public)?;
    let dh2 = simple_ecdh(alice_ephemeral_private, bob_identity_public)?;
    let dh3 = simple_ecdh(alice_ephemeral_private, bob_signed_prekey_public)?;

    let mut dh_concat = Vec::new();
    dh_concat.extend_from_slice(&X3DH_F_PREFIX);
    dh_concat.extend_from_slice(&dh1);
    dh_concat.extend_from_slice(&dh2);
    dh_concat.extend_from_slice(&dh3);

    if let Some(bob_one_time_prekey) = bob_one_time_prekey_public {
        let dh4 = simple_ecdh(alice_ephemeral_private, bob_one_time_prekey)?;
        dh_concat.extend_from_slice(&dh4);
    }

    let shared_secret = hkdf_derive(X3DH_SALT, &dh_concat, X3DH_INFO, KEY_LEN)?;

    Ok(X3DHResult {
        shared_secret,
        associated_data: build_x3dh_aad(alice_identity_public, bob_identity_public),
    })
}

#[hax_lib::include]
#[hax_lib::requires(
    bob_identity_private.len() == 32 &&
    bob_identity_public.len() == 32 &&
    bob_signed_prekey_private.len() == 32 &&
    alice_identity_public.len() == 32 &&
    alice_ephemeral_public.len() == 32
)]
#[hax_lib::ensures(|res| matches!(res, Ok(r) if r.shared_secret.len() == 32) || matches!(res, Err(_)))]
pub fn x3dh_respond_internal(
    bob_identity_private: &[u8],
    bob_identity_public: &[u8],
    bob_signed_prekey_private: &[u8],
    bob_one_time_prekey_private: Option<&[u8]>,
    alice_identity_public: &[u8],
    alice_ephemeral_public: &[u8],
) -> Result<X3DHResult, SignalError> {
    let dh1 = simple_ecdh(bob_signed_prekey_private, alice_identity_public)?;
    let dh2 = simple_ecdh(bob_identity_private, alice_ephemeral_public)?;
    let dh3 = simple_ecdh(bob_signed_prekey_private, alice_ephemeral_public)?;

    let mut dh_concat = Vec::new();
    dh_concat.extend_from_slice(&X3DH_F_PREFIX);
    dh_concat.extend_from_slice(&dh1);
    dh_concat.extend_from_slice(&dh2);
    dh_concat.extend_from_slice(&dh3);

    if let Some(bob_one_time_prekey_private) = bob_one_time_prekey_private {
        let dh4 = simple_ecdh(bob_one_time_prekey_private, alice_ephemeral_public)?;
        dh_concat.extend_from_slice(&dh4);
    }

    let shared_secret = hkdf_derive(X3DH_SALT, &dh_concat, X3DH_INFO, KEY_LEN)?;

    Ok(X3DHResult {
        shared_secret,
        associated_data: build_x3dh_aad(alice_identity_public, bob_identity_public),
    })
}

/// Safe X3DH initiator entry point. Verifies Bob's signed-prekey
/// signature under his Ed25519 identity public key BEFORE deriving the
/// shared secret, per X3DH whitepaper v1.0 §3.3 step 1.
///
/// In the [`crate::types::IdentityKeyPair`] model used here, each
/// identity carries an X25519 keypair (used for DH) AND an Ed25519
/// keypair (used for signing). Alice therefore needs to be told both
/// of Bob's identity public keys: the X25519 half for DH1/DH2 and the
/// Ed25519 half to verify `bob_signed_prekey_signature`.
///
/// The previous-and-still-exported [`x3dh_initiate_internal`] omits the
/// signature check. The ProVerif `signal_complete.pv` model proves
/// secrecy for the safe path; an active attacker who substitutes Bob's
/// bundle on the wire is rejected here.
///
/// Use this function in new code. The `*_internal` variants remain for
/// callers that already verify the signature out-of-band (for example
/// the Sesame session-store layer in libsignal).
#[hax_lib::include]
#[hax_lib::requires(
    alice_identity_x25519_private.len() == 32 &&
    alice_identity_x25519_public.len() == 32 &&
    alice_ephemeral_private.len() == 32 &&
    bob_identity_x25519_public.len() == 32 &&
    bob_identity_ed25519_public.len() == 32 &&
    bob_signed_prekey_public.len() == 32 &&
    bob_signed_prekey_signature.len() == 64
)]
#[hax_lib::ensures(|res| matches!(res, Ok(r) if r.shared_secret.len() == 32) || matches!(res, Err(_)))]
pub fn x3dh_initiate(
    alice_identity_x25519_private: &[u8],
    alice_identity_x25519_public: &[u8],
    alice_ephemeral_private: &[u8],
    bob_identity_x25519_public: &[u8],
    bob_identity_ed25519_public: &[u8],
    bob_signed_prekey_public: &[u8],
    bob_signed_prekey_signature: &[u8],
    bob_one_time_prekey_public: Option<&[u8]>,
) -> Result<X3DHResult, SignalError> {
    let signature_ok = verify_signature_internal(
        bob_identity_ed25519_public,
        bob_signed_prekey_signature,
        bob_signed_prekey_public,
    )?;
    if !signature_ok {
        return Err(SignalError::SignatureVerification(
            "Bob's signed-prekey signature did not verify under his identity key".to_string(),
        ));
    }

    x3dh_initiate_internal(
        alice_identity_x25519_private,
        alice_identity_x25519_public,
        alice_ephemeral_private,
        bob_identity_x25519_public,
        bob_signed_prekey_public,
        bob_one_time_prekey_public,
    )
}
