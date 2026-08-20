//! X3DH (Extended Triple Diffie-Hellman) key agreement protocol
//!
//! This module implements the X3DH key agreement protocol used by Signal
//! to establish shared secrets between two parties. X3DH provides forward
//! secrecy and authentication without requiring both parties to be online
//! simultaneously.

use crate::rust::crypto::uint8_array_to_vec;
use crate::rust::types::X3DHResult;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use web_sys::console;

/// Log messages to the browser console for debugging
///
/// Helps trace the X3DH protocol execution and debug issues
/// during key exchange operations.
#[cfg_attr(coverage_nightly, coverage(off))]
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

/// Internal function to initiate X3DH key exchange - delegates to core
pub(crate) fn x3dh_initiate_internal(
    alice_identity_private: &[u8],
    alice_ephemeral_private: &[u8],
    bob_identity_public: &[u8],
    bob_signed_prekey_public: &[u8],
    bob_one_time_prekey_public: Option<&[u8]>,
) -> Result<X3DHResult, crate::rust::error::SignalError> {
    match signal_protocol_core::x3dh_initiate_internal(
        alice_identity_private,
        alice_ephemeral_private,
        bob_identity_public,
        bob_signed_prekey_public,
        bob_one_time_prekey_public,
    ) {
        Ok(core_result) => Ok(X3DHResult {
            shared_secret: core_result.shared_secret,
            associated_data: core_result.associated_data,
        }),
        Err(e) => Err(e),
    }
}

/// Internal function to respond to X3DH key exchange - delegates to core
pub(crate) fn x3dh_respond_internal(
    bob_identity_private: &[u8],
    bob_signed_prekey_private: &[u8],
    bob_one_time_prekey_private: Option<&[u8]>,
    alice_identity_public: &[u8],
    alice_ephemeral_public: &[u8],
) -> Result<X3DHResult, crate::rust::error::SignalError> {
    match signal_protocol_core::x3dh_respond_internal(
        bob_identity_private,
        bob_signed_prekey_private,
        bob_one_time_prekey_private,
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

/// Initiate X3DH key exchange (Alice's side)
///
/// This function performs the X3DH key agreement from the initiator's perspective.
/// Alice combines her keys with Bob's prekeys to compute a shared secret that
/// both parties can independently derive.
///
/// ## X3DH Protocol Overview
/// The X3DH protocol performs multiple Diffie-Hellman computations:
/// 1. DH1: Alice_Identity_Private × Bob_SignedPrekey_Public
/// 2. DH2: Alice_Ephemeral_Private × Bob_Identity_Public  
/// 3. DH3: Alice_Ephemeral_Private × Bob_SignedPrekey_Public
/// 4. DH4: Alice_Ephemeral_Private × Bob_OneTimePrekey_Public (optional)
///
/// The results are concatenated and fed into HKDF to derive the final shared secret.
///
/// ## Security Properties
/// - **Forward Secrecy**: Compromise of long-term keys doesn't affect past sessions
/// - **Authentication**: Both parties prove their identity through key ownership
/// - **Asynchronous**: Bob doesn't need to be online during key exchange
/// - **Deniability**: No long-term proof of participation in conversations
///
/// ## Parameters
/// - `alice_identity_private`: Alice's long-term identity private key (32 bytes)
/// - `alice_ephemeral_private`: Alice's session-specific ephemeral private key (32 bytes)
/// - `bob_identity_public`: Bob's identity public key (32 bytes)
/// - `bob_signed_prekey_public`: Bob's signed prekey public key (32 bytes)
/// - `bob_one_time_prekey_public`: Optional one-time prekey for additional forward secrecy
///
/// ## Returns
/// An `X3DHResult` containing the shared secret and associated data
///
/// ## Example Usage
/// ```rust
/// let result = x3dh_initiate(
///     &alice_identity_private,
///     &alice_ephemeral_private,
///     &bob_identity_public,
///     &bob_signed_prekey_public,
///     Some(bob_one_time_prekey_public)
/// )?;
/// let shared_secret = result.shared_secret();
/// ```
#[cfg_attr(coverage_nightly, coverage(off))]
#[wasm_bindgen]
pub fn x3dh_initiate(
    alice_identity_private: &Uint8Array,
    alice_ephemeral_private: &Uint8Array,
    bob_identity_public: &Uint8Array,
    bob_signed_prekey_public: &Uint8Array,
    bob_one_time_prekey_public: Option<Uint8Array>,
) -> Result<X3DHResult, JsValue> {
    log("Initiating X3DH key exchange (Alice side)");

    // Convert JavaScript arrays to Rust vectors
    let alice_identity_private_bytes = uint8_array_to_vec(alice_identity_private);
    let alice_ephemeral_private_bytes = uint8_array_to_vec(alice_ephemeral_private);
    let bob_identity_public_bytes = uint8_array_to_vec(bob_identity_public);
    let bob_signed_prekey_public_bytes = uint8_array_to_vec(bob_signed_prekey_public);

    let bob_one_time_prekey_opt = bob_one_time_prekey_public
        .as_ref()
        .map(|k| uint8_array_to_vec(k));

    match x3dh_initiate_internal(
        &alice_identity_private_bytes,
        &alice_ephemeral_private_bytes,
        &bob_identity_public_bytes,
        &bob_signed_prekey_public_bytes,
        bob_one_time_prekey_opt.as_ref().map(|v| v.as_slice()),
    ) {
        Ok(result) => {
            log("X3DH initiation completed successfully");
            Ok(result)
        }
        Err(e) => Err(JsValue::from_str(&e.to_string())),
    }
}

/// Respond to X3DH key exchange (Bob's side)
///
/// This function performs the X3DH key agreement from the responder's perspective.
/// Bob uses his prekeys and Alice's ephemeral key to compute the same shared secret
/// that Alice derived on her side.
///
/// ## Protocol Symmetry
/// Bob performs the exact same DH computations as Alice, but uses his private keys
/// instead of Alice's. The commutativity property of our simplified ECDH ensures
/// that both parties compute identical shared secrets.
///
/// ## Key Derivation Order
/// Bob must perform the DH computations in the same order as Alice:
/// 1. DH1: Bob_SignedPrekey_Private × Alice_Identity_Public (= Alice's DH1)
/// 2. DH2: Bob_Identity_Private × Alice_Ephemeral_Public (= Alice's DH2)
/// 3. DH3: Bob_SignedPrekey_Private × Alice_Ephemeral_Public (= Alice's DH3)
/// 4. DH4: Bob_OneTimePrekey_Private × Alice_Ephemeral_Public (= Alice's DH4, optional)
///
/// ## Parameters
/// - `bob_identity_private`: Bob's long-term identity private key (32 bytes)
/// - `bob_signed_prekey_private`: Bob's signed prekey private key (32 bytes)
/// - `bob_one_time_prekey_private`: Optional one-time prekey private key (32 bytes)
/// - `alice_identity_public`: Alice's identity public key (32 bytes)
/// - `alice_ephemeral_public`: Alice's ephemeral public key from the key exchange (32 bytes)
///
/// ## Returns
/// An `X3DHResult` containing the same shared secret Alice computed
///
/// ## Example Usage
/// ```rust
/// let result = x3dh_respond(
///     &bob_identity_private,
///     &bob_signed_prekey_private,
///     Some(bob_one_time_prekey_private),
///     &alice_identity_public,
///     &alice_ephemeral_public
/// )?;
/// let shared_secret = result.shared_secret();
/// ```
#[cfg_attr(coverage_nightly, coverage(off))]
#[wasm_bindgen]
pub fn x3dh_respond(
    bob_identity_private: &Uint8Array,
    bob_signed_prekey_private: &Uint8Array,
    bob_one_time_prekey_private: Option<Uint8Array>,
    alice_identity_public: &Uint8Array,
    alice_ephemeral_public: &Uint8Array,
) -> Result<X3DHResult, JsValue> {
    log("Responding to X3DH key exchange (Bob side)");

    // Convert JavaScript arrays to Rust vectors
    let bob_identity_private_bytes = uint8_array_to_vec(bob_identity_private);
    let bob_signed_prekey_private_bytes = uint8_array_to_vec(bob_signed_prekey_private);
    let alice_identity_public_bytes = uint8_array_to_vec(alice_identity_public);
    let alice_ephemeral_public_bytes = uint8_array_to_vec(alice_ephemeral_public);

    let bob_one_time_prekey_opt = bob_one_time_prekey_private.as_ref().map(|k| {
        let bytes = uint8_array_to_vec(k);
        bytes
    });

    match x3dh_respond_internal(
        &bob_identity_private_bytes,
        &bob_signed_prekey_private_bytes,
        bob_one_time_prekey_opt.as_ref().map(|v| v.as_slice()),
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

#[cfg(test)]
#[allow(dead_code)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::rust::keys::*;
    use wasm_bindgen_test::*;

    /// Test complete X3DH key exchange without one-time prekey
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen_test]
    fn test_x3dh_without_one_time_prekey() {
        // Generate keys for Alice
        let alice_identity = generate_identity_keypair().unwrap();
        let alice_ephemeral = generate_ephemeral_keypair().unwrap();

        // Generate keys for Bob
        let bob_identity = generate_identity_keypair().unwrap();
        let bob_signed_prekey = generate_signed_prekey().unwrap();

        // Alice initiates X3DH
        let alice_result = x3dh_initiate(
            &alice_identity.private_key(),
            &alice_ephemeral.private_key(),
            &bob_identity.public_key(),
            &bob_signed_prekey.public_key(),
            None,
        )
        .unwrap();

        // Bob responds to X3DH
        let bob_result = x3dh_respond(
            &bob_identity.private_key(),
            &bob_signed_prekey.private_key(),
            None,
            &alice_identity.public_key(),
            &alice_ephemeral.public_key(),
        )
        .unwrap();

        // Both parties should derive the same shared secret
        assert_eq!(
            alice_result.shared_secret().to_vec(),
            bob_result.shared_secret().to_vec()
        );
        assert_eq!(alice_result.shared_secret().length(), 32);
        assert_eq!(
            alice_result.associated_data().to_vec(),
            bob_result.associated_data().to_vec()
        );
    }

    /// Test complete X3DH key exchange with one-time prekey
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen_test]
    fn test_x3dh_with_one_time_prekey() {
        // Generate keys for Alice
        let alice_identity = generate_identity_keypair().unwrap();
        let alice_ephemeral = generate_ephemeral_keypair().unwrap();

        // Generate keys for Bob
        let bob_identity = generate_identity_keypair().unwrap();
        let bob_signed_prekey = generate_signed_prekey().unwrap();
        let bob_one_time_prekey = generate_one_time_prekey().unwrap();

        // Alice initiates X3DH with one-time prekey
        let alice_result = x3dh_initiate(
            &alice_identity.private_key(),
            &alice_ephemeral.private_key(),
            &bob_identity.public_key(),
            &bob_signed_prekey.public_key(),
            Some(bob_one_time_prekey.public_key()),
        )
        .unwrap();

        // Bob responds to X3DH with one-time prekey
        let bob_result = x3dh_respond(
            &bob_identity.private_key(),
            &bob_signed_prekey.private_key(),
            Some(bob_one_time_prekey.private_key()),
            &alice_identity.public_key(),
            &alice_ephemeral.public_key(),
        )
        .unwrap();

        // Both parties should derive the same shared secret
        assert_eq!(
            alice_result.shared_secret().to_vec(),
            bob_result.shared_secret().to_vec()
        );
        assert_eq!(alice_result.shared_secret().length(), 32);
        assert_eq!(
            alice_result.associated_data().to_vec(),
            bob_result.associated_data().to_vec()
        );
    }

    /// Test that different key sets produce different shared secrets
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen_test]
    fn test_x3dh_uniqueness() {
        // First key exchange
        let alice_identity1 = generate_identity_keypair().unwrap();
        let alice_ephemeral1 = generate_ephemeral_keypair().unwrap();
        let bob_identity1 = generate_identity_keypair().unwrap();
        let bob_signed_prekey1 = generate_signed_prekey().unwrap();

        let result1 = x3dh_initiate(
            &alice_identity1.private_key(),
            &alice_ephemeral1.private_key(),
            &bob_identity1.public_key(),
            &bob_signed_prekey1.public_key(),
            None,
        )
        .unwrap();

        // Second key exchange with different keys
        let alice_identity2 = generate_identity_keypair().unwrap();
        let alice_ephemeral2 = generate_ephemeral_keypair().unwrap();
        let bob_identity2 = generate_identity_keypair().unwrap();
        let bob_signed_prekey2 = generate_signed_prekey().unwrap();

        let result2 = x3dh_initiate(
            &alice_identity2.private_key(),
            &alice_ephemeral2.private_key(),
            &bob_identity2.public_key(),
            &bob_signed_prekey2.public_key(),
            None,
        )
        .unwrap();

        // Different keys should produce different shared secrets
        assert_ne!(
            result1.shared_secret().to_vec(),
            result2.shared_secret().to_vec()
        );
    }
}
