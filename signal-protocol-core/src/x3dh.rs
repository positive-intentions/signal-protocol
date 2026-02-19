//! X3DH (Extended Triple Diffie-Hellman) key agreement protocol

use crate::crypto::{hkdf_derive, simple_ecdh};
use crate::error::SignalError;
use crate::types::X3DHResult;

#[hax_lib::include]
pub fn x3dh_initiate_internal(
    alice_identity_private: &[u8],
    alice_ephemeral_private: &[u8],
    bob_identity_public: &[u8],
    bob_signed_prekey_public: &[u8],
    bob_one_time_prekey_public: Option<&[u8]>,
) -> Result<X3DHResult, SignalError> {
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

    let associated_data = b"X3DH_Key_Exchange";

    Ok(X3DHResult {
        shared_secret,
        associated_data: associated_data.to_vec(),
    })
}

#[hax_lib::include]
pub fn x3dh_respond_internal(
    bob_identity_private: &[u8],
    bob_signed_prekey_private: &[u8],
    bob_one_time_prekey_private: Option<&[u8]>,
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

    let associated_data = b"X3DH_Key_Exchange";

    Ok(X3DHResult {
        shared_secret,
        associated_data: associated_data.to_vec(),
    })
}
