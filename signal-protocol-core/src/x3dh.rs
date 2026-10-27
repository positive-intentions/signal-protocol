//! X3DH (Extended Triple Diffie-Hellman) key agreement protocol

use crate::crypto::{hkdf_derive, simple_ecdh};
use crate::error::SignalError;
use crate::keys::verify_signed_prekey;
use crate::types::X3DHResult;

/// Build X3DH associated data as `IK_A || IK_B` (SP-2026-005).
pub fn x3dh_associated_data(alice_identity_public: &[u8], bob_identity_public: &[u8]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(alice_identity_public.len() + bob_identity_public.len());
    ad.extend_from_slice(alice_identity_public);
    ad.extend_from_slice(bob_identity_public);
    ad
}

#[hax_lib::include]
pub fn x3dh_initiate_internal(
    alice_identity_private: &[u8],
    alice_ephemeral_private: &[u8],
    alice_identity_public: &[u8],
    bob_identity_public: &[u8],
    bob_signed_prekey_public: &[u8],
    bob_signed_prekey_signature: &[u8],
    bob_one_time_prekey_public: Option<&[u8]>,
) -> Result<X3DHResult, SignalError> {
    // SP-2026-004: verify SPK inside initiate (fail closed).
    verify_signed_prekey(
        bob_identity_public,
        bob_signed_prekey_public,
        bob_signed_prekey_signature,
    )?;

    let dh1 = simple_ecdh(alice_identity_private, bob_signed_prekey_public)?;
    let dh2 = simple_ecdh(alice_ephemeral_private, bob_identity_public)?;
    let dh3 = simple_ecdh(alice_ephemeral_private, bob_signed_prekey_public)?;

    let mut dh_concat = Vec::new();
    dh_concat.extend_from_slice(&dh1);
    dh_concat.extend_from_slice(&dh2);
    dh_concat.extend_from_slice(&dh3);

    if let Some(bob_one_time_prekey) = bob_one_time_prekey_public {
        let dh4 = simple_ecdh(alice_ephemeral_private, bob_one_time_prekey)?;
        dh_concat.extend_from_slice(&dh4);
    }

    let salt = b"Signal_X3DH_Salt";
    let info = b"Signal_X3DH_Key_Derivation";

    let shared_secret = hkdf_derive(salt, &dh_concat, info, 32)?;
    let associated_data = x3dh_associated_data(alice_identity_public, bob_identity_public);

    Ok(X3DHResult {
        shared_secret,
        associated_data,
    })
}

#[hax_lib::include]
pub fn x3dh_respond_internal(
    bob_identity_private: &[u8],
    bob_signed_prekey_private: &[u8],
    bob_one_time_prekey_private: Option<&[u8]>,
    bob_identity_public: &[u8],
    alice_identity_public: &[u8],
    alice_ephemeral_public: &[u8],
) -> Result<X3DHResult, SignalError> {
    let dh1 = simple_ecdh(bob_signed_prekey_private, alice_identity_public)?;
    let dh2 = simple_ecdh(bob_identity_private, alice_ephemeral_public)?;
    let dh3 = simple_ecdh(bob_signed_prekey_private, alice_ephemeral_public)?;

    let mut dh_concat = Vec::new();
    dh_concat.extend_from_slice(&dh1);
    dh_concat.extend_from_slice(&dh2);
    dh_concat.extend_from_slice(&dh3);

    if let Some(bob_one_time_prekey_private) = bob_one_time_prekey_private {
        let dh4 = simple_ecdh(bob_one_time_prekey_private, alice_ephemeral_public)?;
        dh_concat.extend_from_slice(&dh4);
    }

    let salt = b"Signal_X3DH_Salt";
    let info = b"Signal_X3DH_Key_Derivation";

    let shared_secret = hkdf_derive(salt, &dh_concat, info, 32)?;
    let associated_data = x3dh_associated_data(alice_identity_public, bob_identity_public);

    Ok(X3DHResult {
        shared_secret,
        associated_data,
    })
}

#[cfg(all(test, feature = "crypto-backend"))]
mod tests {
    use super::*;
    use crate::keys::{
        generate_ephemeral_keypair, generate_identity_keypair, generate_one_time_prekey,
        generate_signed_prekey, sign_prekey,
    };

    #[test]
    fn x3dh_symmetric_with_otpk() {
        let alice_id = generate_identity_keypair();
        let alice_eph = generate_ephemeral_keypair();
        let bob_id = generate_identity_keypair();
        let bob_spk = generate_signed_prekey();
        let bob_otpk = generate_one_time_prekey();
        let sig = sign_prekey(&bob_id.private_key, &bob_spk.public_key).unwrap();

        let init = x3dh_initiate_internal(
            &alice_id.private_key,
            &alice_eph.private_key,
            &alice_id.public_key,
            &bob_id.public_key,
            &bob_spk.public_key,
            &sig,
            Some(&bob_otpk.public_key),
        )
        .unwrap();

        let resp = x3dh_respond_internal(
            &bob_id.private_key,
            &bob_spk.private_key,
            Some(&bob_otpk.private_key),
            &bob_id.public_key,
            &alice_id.public_key,
            &alice_eph.public_key,
        )
        .unwrap();

        assert_eq!(init.shared_secret, resp.shared_secret);
        assert_eq!(init.associated_data, resp.associated_data);
        assert_eq!(
            init.associated_data,
            x3dh_associated_data(&alice_id.public_key, &bob_id.public_key)
        );
    }

    #[test]
    fn x3dh_rejects_bad_spk_signature() {
        let alice_id = generate_identity_keypair();
        let alice_eph = generate_ephemeral_keypair();
        let bob_id = generate_identity_keypair();
        let bob_spk = generate_signed_prekey();
        let err = x3dh_initiate_internal(
            &alice_id.private_key,
            &alice_eph.private_key,
            &alice_id.public_key,
            &bob_id.public_key,
            &bob_spk.public_key,
            &[0u8; 64],
            None,
        )
        .unwrap_err();
        assert!(matches!(err, SignalError::SignatureVerification(_)));
    }

    #[test]
    fn x3dh_symmetric_without_otpk() {
        let alice_id = generate_identity_keypair();
        let alice_eph = generate_ephemeral_keypair();
        let bob_id = generate_identity_keypair();
        let bob_spk = generate_signed_prekey();
        let sig = sign_prekey(&bob_id.private_key, &bob_spk.public_key).unwrap();

        let init = x3dh_initiate_internal(
            &alice_id.private_key,
            &alice_eph.private_key,
            &alice_id.public_key,
            &bob_id.public_key,
            &bob_spk.public_key,
            &sig,
            None,
        )
        .unwrap();

        let resp = x3dh_respond_internal(
            &bob_id.private_key,
            &bob_spk.private_key,
            None,
            &bob_id.public_key,
            &alice_id.public_key,
            &alice_eph.public_key,
        )
        .unwrap();

        assert_eq!(init.shared_secret, resp.shared_secret);
        assert_eq!(init.shared_secret.len(), 32);
    }

    #[test]
    fn x3dh_bad_key_length() {
        let err = x3dh_initiate_internal(
            &[0u8; 16], &[0u8; 32], &[0u8; 32], &[0u8; 32], &[0u8; 32], &[0u8; 64], None,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SignalError::InvalidInput(_) | SignalError::SignatureVerification(_)
        ));
    }
}
