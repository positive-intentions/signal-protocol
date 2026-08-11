//! Core cryptographic operations for Signal Protocol
//!
//! This module implements the fundamental cryptographic operations used in the
//! Signal Protocol, including digital signatures and ECDH key agreement.
//!
//! **PRODUCTION IMPLEMENTATION**: Uses real X25519 ECDH and Ed25519 signatures

use crate::rust::error::SignalError;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use web_sys::console;

/// Utility function to convert JavaScript Uint8Array to Rust Vec<u8>
///
/// This helper function bridges the gap between JavaScript typed arrays
/// and Rust vectors, enabling seamless data transfer across the WASM boundary.
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) fn uint8_array_to_vec(arr: &Uint8Array) -> Vec<u8> {
    arr.to_vec()
}

/// Log messages to the browser console for debugging
///
/// **SECURITY NOTE**: Only logs non-sensitive operational information.
/// Never logs keys, secrets, or other cryptographic material.
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

/// Validate that a public key is a valid X25519 point - delegates to core
pub(crate) fn validate_x25519_public_key(public_key: &[u8]) -> Result<(), SignalError> {
    signal_protocol_core::validate_x25519_public_key(public_key)
}

/// Perform X25519 ECDH - delegates to core
pub(crate) fn x25519_ecdh(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, SignalError> {
    signal_protocol_core::crypto::x25519_ecdh(private_key, public_key)
}

/// Legacy name for ECDH - kept for compatibility
///
/// Returns Result for panic-free operation. Callers should use ? or .unwrap().
pub(crate) fn simple_ecdh(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, SignalError> {
    signal_protocol_core::simple_ecdh(private_key, public_key)
}

/// Internal function to sign data - delegates to core
pub(crate) fn sign_data_internal(private_key: &[u8], data: &[u8]) -> Result<Vec<u8>, SignalError> {
    signal_protocol_core::sign_data_internal(private_key, data)
}

/// Internal function to verify signature - delegates to core
pub(crate) fn verify_signature_internal(
    public_key: &[u8],
    signature: &[u8],
    data: &[u8],
) -> Result<bool, SignalError> {
    signal_protocol_core::verify_signature_internal(public_key, signature, data)
}

/// Sign data using Ed25519 digital signature algorithm
///
/// Creates a cryptographically secure digital signature that proves the data
/// was signed by the holder of the corresponding Ed25519 private key.
/// The signature can be verified by anyone who has the public key.
///
/// ## Implementation
/// Uses Ed25519 (Edwards-curve Digital Signature Algorithm) which provides:
/// - 128-bit security level
/// - Deterministic signatures (same input = same signature)
/// - Small signature size (64 bytes)
/// - Fast verification
///
/// ## Usage Example
/// ```javascript
/// const signature = sign_data(privateKey, message);
/// const isValid = verify_signature(publicKey, signature, message);
/// ```
///
/// ## Parameters
/// - `private_key`: The signer's Ed25519 private key as Uint8Array (must be 32 bytes)
/// - `data`: The data to sign as Uint8Array
///
/// ## Returns
/// A Uint8Array containing the 64-byte Ed25519 signature
///
/// ## Errors
/// - Returns error if private key is not exactly 32 bytes
/// - Returns error if signing operation fails
#[cfg_attr(coverage_nightly, coverage(off))]
#[wasm_bindgen]
pub fn sign_data(private_key: &Uint8Array, data: &Uint8Array) -> Result<Uint8Array, JsValue> {
    log("Signing data with Ed25519");

    let private_key_bytes = uint8_array_to_vec(private_key);
    let data_bytes = uint8_array_to_vec(data);

    match sign_data_internal(&private_key_bytes, &data_bytes) {
        Ok(signature_bytes) => Ok(Uint8Array::from(signature_bytes.as_slice())),
        Err(e) => Err(JsValue::from_str(&e.to_string())),
    }
}

/// Verify an Ed25519 digital signature
///
/// Verifies that a signature was created by the holder of the private key
/// corresponding to the given Ed25519 public key. This ensures message
/// authenticity and integrity through elliptic curve cryptography.
///
/// ## Security Properties
/// - **Unforgeability**: Cannot create valid signatures without private key
/// - **Non-repudiation**: Signer cannot deny creating the signature
/// - **Integrity**: Any modification to data invalidates the signature
/// - **Constant-time**: Verification takes same time regardless of validity
///
/// ## Usage Example
/// ```javascript
/// const isValid = verify_signature(publicKey, signature, originalMessage);
/// if (isValid) {
///     console.log("Signature is valid!");
/// }
/// ```
///
/// ## Parameters
/// - `public_key`: The signer's Ed25519 public key as Uint8Array (must be 32 bytes)
/// - `signature`: The Ed25519 signature to verify as Uint8Array (must be 64 bytes)
/// - `data`: The original signed data as Uint8Array
///
/// ## Returns
/// `true` if the signature is valid, `false` otherwise
///
/// ## Errors
/// - Returns error if public key is not exactly 32 bytes
/// - Returns error if signature is not exactly 64 bytes
/// - Returns error if key format is invalid
#[cfg_attr(coverage_nightly, coverage(off))]
#[wasm_bindgen]
pub fn verify_signature(
    public_key: &Uint8Array,
    signature: &Uint8Array,
    data: &Uint8Array,
) -> Result<bool, JsValue> {
    log("Verifying signature with Ed25519");

    let public_key_bytes = uint8_array_to_vec(public_key);
    let signature_bytes = uint8_array_to_vec(signature);
    let data_bytes = uint8_array_to_vec(data);

    match verify_signature_internal(&public_key_bytes, &signature_bytes, &data_bytes) {
        Ok(is_valid) => Ok(is_valid),
        Err(e) => Err(JsValue::from_str(&e.to_string())),
    }
}

/// Internal signature functions for compatibility (deprecated - use Ed25519 above)
///
/// These functions are kept for backward compatibility but should not be used
/// in new code. They previously implemented fake signatures using HMAC.

#[allow(dead_code)]
pub(crate) fn simple_sign(_private_key: &[u8], _data: &[u8]) -> Vec<u8> {
    panic!("simple_sign is deprecated - use Ed25519 sign_data instead");
}

#[allow(dead_code)]
pub(crate) fn simple_verify(_public_key: &[u8], _signature: &[u8], _data: &[u8]) -> bool {
    panic!("simple_verify is deprecated - use Ed25519 verify_signature instead");
}

#[cfg(test)]
#[allow(dead_code)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::rust::keys::generate_identity_keypair;
    use ed25519_dalek::SigningKey;
    use rand::RngCore;
    use wasm_bindgen_test::*;

    /// Test X25519 ECDH commutativity (real elliptic curve DH)
    ///
    /// Tests that A(priv_a, pub_b) == B(priv_b, pub_a)
    /// This is a fundamental property of Diffie-Hellman key exchange
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen_test]
    fn test_x25519_ecdh_commutativity() {
        // Generate two real X25519 key pairs
        let keypair_a = generate_identity_keypair().unwrap();
        let keypair_b = generate_identity_keypair().unwrap();

        // Extract keys
        let priv_a = keypair_a.private_key().to_vec();
        let pub_a = keypair_a.public_key().to_vec();
        let priv_b = keypair_b.private_key().to_vec();
        let pub_b = keypair_b.public_key().to_vec();

        // Test commutativity: A(priv_a, pub_b) should equal B(priv_b, pub_a)
        let shared_secret_ab = x25519_ecdh(&priv_a, &pub_b).unwrap();
        let shared_secret_ba = x25519_ecdh(&priv_b, &pub_a).unwrap();

        assert_eq!(
            shared_secret_ab, shared_secret_ba,
            "ECDH must be commutative"
        );
        assert_eq!(shared_secret_ab.len(), 32, "Shared secret must be 32 bytes");
    }

    /// Test that different key pairs produce different shared secrets
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen_test]
    fn test_x25519_ecdh_uniqueness() {
        let keypair_a = generate_identity_keypair().unwrap();
        let keypair_b = generate_identity_keypair().unwrap();
        let keypair_c = generate_identity_keypair().unwrap();

        let priv_a = keypair_a.private_key().to_vec();
        let pub_b = keypair_b.public_key().to_vec();
        let pub_c = keypair_c.public_key().to_vec();

        // Different public keys should produce different shared secrets
        let shared_ab = x25519_ecdh(&priv_a, &pub_b).unwrap();
        let shared_ac = x25519_ecdh(&priv_a, &pub_c).unwrap();

        assert_ne!(
            shared_ab, shared_ac,
            "Different keys must produce different secrets"
        );
    }

    /// Test X25519 key validation
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen_test]
    fn test_x25519_key_validation() {
        // Valid 32-byte key
        let valid_key = vec![1u8; 32];
        assert!(validate_x25519_public_key(&valid_key).is_ok());

        // Invalid lengths
        let short_key = vec![1u8; 16];
        let long_key = vec![1u8; 64];
        assert!(validate_x25519_public_key(&short_key).is_err());
        assert!(validate_x25519_public_key(&long_key).is_err());
    }

    /// Test Ed25519 signature creation and verification
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen_test]
    fn test_ed25519_signatures() {
        // Generate a signing key pair
        let mut signing_key_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut signing_key_bytes);

        let signing_key = SigningKey::from_bytes(&signing_key_bytes);
        let verifying_key = signing_key.verifying_key();

        let private_key = Uint8Array::from(signing_key_bytes.as_slice());
        let public_key = Uint8Array::from(&verifying_key.as_bytes()[..]);
        let data = Uint8Array::from("Hello, Ed25519!".as_bytes());

        // Sign the data
        let signature = sign_data(&private_key, &data).unwrap();
        assert_eq!(signature.length(), 64, "Ed25519 signatures are 64 bytes");

        // Verify with correct public key
        let is_valid = verify_signature(&public_key, &signature, &data).unwrap();
        assert!(is_valid, "Valid signature must verify");

        // Verify with wrong data should fail
        let wrong_data = Uint8Array::from("Wrong message!".as_bytes());
        let is_invalid = verify_signature(&public_key, &signature, &wrong_data).unwrap();
        assert!(!is_invalid, "Invalid signature must not verify");
    }

    /// Test Ed25519 signature unforgeability
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen_test]
    fn test_ed25519_unforgeability() {
        // Generate two different key pairs
        let mut key_a_bytes = [0u8; 32];
        let mut key_b_bytes = [1u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key_a_bytes);
        rand::rngs::OsRng.fill_bytes(&mut key_b_bytes);

        let signing_key_a = SigningKey::from_bytes(&key_a_bytes);
        let verifying_key_a = signing_key_a.verifying_key();
        let verifying_key_b = SigningKey::from_bytes(&key_b_bytes).verifying_key();

        let private_key_a = Uint8Array::from(key_a_bytes.as_slice());
        let public_key_a = Uint8Array::from(&verifying_key_a.as_bytes()[..]);
        let public_key_b = Uint8Array::from(&verifying_key_b.as_bytes()[..]);
        let data = Uint8Array::from("Test message".as_bytes());

        // Sign with key A
        let signature = sign_data(&private_key_a, &data).unwrap();

        // Verify with key A should succeed
        let valid_a = verify_signature(&public_key_a, &signature, &data).unwrap();
        assert!(valid_a, "Signature must verify with correct key");

        // Verify with key B should fail (unforgeability)
        let valid_b = verify_signature(&public_key_b, &signature, &data).unwrap();
        assert!(!valid_b, "Signature must not verify with different key");
    }

    /// Test Ed25519 deterministic signatures
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen_test]
    fn test_ed25519_determinism() {
        let mut key_bytes = [42u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key_bytes);

        let private_key = Uint8Array::from(key_bytes.as_slice());
        let data = Uint8Array::from("Same data".as_bytes());

        // Sign twice with same key and data
        let signature1 = sign_data(&private_key, &data).unwrap();
        let signature2 = sign_data(&private_key, &data).unwrap();

        // Ed25519 signatures are deterministic
        assert_eq!(
            signature1.to_vec(),
            signature2.to_vec(),
            "Ed25519 signatures must be deterministic"
        );
    }

    /// Test error handling for invalid key sizes
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen_test]
    fn test_invalid_key_sizes() {
        let short_key = Uint8Array::from(&[1u8; 16][..]); // Too short
        let data = Uint8Array::from("test".as_bytes());

        // Should fail with short private key for signing
        let result = sign_data(&short_key, &data);
        assert!(result.is_err(), "Signing with short key must fail");

        // Should fail with short public key for verification
        let valid_private_key = Uint8Array::from(&[1u8; 32][..]);
        let signature = sign_data(&valid_private_key, &data).unwrap();
        let verify_result = verify_signature(&short_key, &signature, &data);
        assert!(
            verify_result.is_err(),
            "Verification with short key must fail"
        );
    }

    /// Test error handling for invalid signature sizes
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen_test]
    fn test_invalid_signature_size() {
        let mut key_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key_bytes);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key = signing_key.verifying_key();

        let public_key = Uint8Array::from(&verifying_key.as_bytes()[..]);
        let data = Uint8Array::from("test".as_bytes());
        let short_signature = Uint8Array::from(&[0u8; 32][..]); // Too short (64 required)

        let result = verify_signature(&public_key, &short_signature, &data);
        assert!(
            result.is_err(),
            "Verification with short signature must fail"
        );
    }

    /// Test ECDH with invalid inputs
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen_test]
    fn test_ecdh_invalid_inputs() {
        let valid_key = vec![1u8; 32];
        let short_key = vec![1u8; 16];
        let long_key = vec![1u8; 64];

        // Invalid private key length
        assert!(x25519_ecdh(&short_key, &valid_key).is_err());
        assert!(x25519_ecdh(&long_key, &valid_key).is_err());

        // Invalid public key length
        assert!(x25519_ecdh(&valid_key, &short_key).is_err());
        assert!(x25519_ecdh(&valid_key, &long_key).is_err());
    }
}
