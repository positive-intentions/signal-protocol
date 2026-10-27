//! X3DH key agreement — WASM wrapper around signal-protocol-core.

use crate::rust::crypto::uint8_array_to_vec;
use crate::rust::types::X3DHResult;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use web_sys::console;

fn log(s: &str) {
    #[cfg(target_arch = "wasm32")]
    {
        console::log_1(&JsValue::from_str(s));
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        eprintln!("{}", s);
    }
}

pub(crate) fn x3dh_initiate_internal(
    alice_identity_private: &[u8],
    alice_ephemeral_private: &[u8],
    alice_identity_public: &[u8],
    bob_identity_public: &[u8],
    bob_signed_prekey_public: &[u8],
    bob_signed_prekey_signature: &[u8],
    bob_one_time_prekey_public: Option<&[u8]>,
) -> Result<X3DHResult, crate::rust::error::SignalError> {
    match signal_protocol_core::x3dh_initiate_internal(
        alice_identity_private,
        alice_ephemeral_private,
        alice_identity_public,
        bob_identity_public,
        bob_signed_prekey_public,
        bob_signed_prekey_signature,
        bob_one_time_prekey_public,
    ) {
        Ok(core_result) => Ok(X3DHResult {
            shared_secret: core_result.shared_secret,
            associated_data: core_result.associated_data,
        }),
        Err(e) => Err(e),
    }
}

pub(crate) fn x3dh_respond_internal(
    bob_identity_private: &[u8],
    bob_signed_prekey_private: &[u8],
    bob_one_time_prekey_private: Option<&[u8]>,
    bob_identity_public: &[u8],
    alice_identity_public: &[u8],
    alice_ephemeral_public: &[u8],
) -> Result<X3DHResult, crate::rust::error::SignalError> {
    match signal_protocol_core::x3dh_respond_internal(
        bob_identity_private,
        bob_signed_prekey_private,
        bob_one_time_prekey_private,
        bob_identity_public,
        alice_identity_public,
        alice_ephemeral_public,
    ) {
        Ok(core_result) => Ok(X3DHResult {
            shared_secret: core_result.shared_secret,
            associated_data: core_result.associated_data,
        }),
        Err(e) => Err(e),
    }
}

#[wasm_bindgen]
pub fn x3dh_initiate(
    alice_identity_private: &Uint8Array,
    alice_ephemeral_private: &Uint8Array,
    alice_identity_public: &Uint8Array,
    bob_identity_public: &Uint8Array,
    bob_signed_prekey_public: &Uint8Array,
    bob_signed_prekey_signature: &Uint8Array,
    bob_one_time_prekey_public: Option<Uint8Array>,
) -> Result<X3DHResult, JsValue> {
    log("Initiating X3DH key exchange (Alice side)");

    let alice_identity_private_bytes = uint8_array_to_vec(alice_identity_private);
    let alice_ephemeral_private_bytes = uint8_array_to_vec(alice_ephemeral_private);
    let alice_identity_public_bytes = uint8_array_to_vec(alice_identity_public);
    let bob_identity_public_bytes = uint8_array_to_vec(bob_identity_public);
    let bob_signed_prekey_public_bytes = uint8_array_to_vec(bob_signed_prekey_public);
    let bob_signed_prekey_signature_bytes = uint8_array_to_vec(bob_signed_prekey_signature);

    let bob_one_time_prekey_opt = bob_one_time_prekey_public
        .as_ref()
        .map(|k| uint8_array_to_vec(k));

    match x3dh_initiate_internal(
        &alice_identity_private_bytes,
        &alice_ephemeral_private_bytes,
        &alice_identity_public_bytes,
        &bob_identity_public_bytes,
        &bob_signed_prekey_public_bytes,
        &bob_signed_prekey_signature_bytes,
        bob_one_time_prekey_opt.as_ref().map(|v| v.as_slice()),
    ) {
        Ok(result) => {
            log("X3DH initiation completed successfully");
            Ok(result)
        }
        Err(e) => Err(JsValue::from_str(&e.to_string())),
    }
}

#[wasm_bindgen]
pub fn x3dh_respond(
    bob_identity_private: &Uint8Array,
    bob_signed_prekey_private: &Uint8Array,
    bob_one_time_prekey_private: Option<Uint8Array>,
    bob_identity_public: &Uint8Array,
    alice_identity_public: &Uint8Array,
    alice_ephemeral_public: &Uint8Array,
) -> Result<X3DHResult, JsValue> {
    log("Responding to X3DH key exchange (Bob side)");

    let bob_identity_private_bytes = uint8_array_to_vec(bob_identity_private);
    let bob_signed_prekey_private_bytes = uint8_array_to_vec(bob_signed_prekey_private);
    let bob_identity_public_bytes = uint8_array_to_vec(bob_identity_public);
    let alice_identity_public_bytes = uint8_array_to_vec(alice_identity_public);
    let alice_ephemeral_public_bytes = uint8_array_to_vec(alice_ephemeral_public);

    let bob_one_time_prekey_opt = bob_one_time_prekey_private
        .as_ref()
        .map(|k| uint8_array_to_vec(k));

    match x3dh_respond_internal(
        &bob_identity_private_bytes,
        &bob_signed_prekey_private_bytes,
        bob_one_time_prekey_opt.as_ref().map(|v| v.as_slice()),
        &bob_identity_public_bytes,
        &alice_identity_public_bytes,
        &alice_ephemeral_public_bytes,
    ) {
        Ok(result) => {
            log("X3DH response completed successfully");
            Ok(result)
        }
        Err(e) => Err(JsValue::from_str(&e.to_string())),
    }
}
