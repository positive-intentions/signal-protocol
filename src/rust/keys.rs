//! Cryptographic key generation for Signal Protocol
//!
//! Thin WASM wrapper around signal-protocol-core key generation.

use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use web_sys::console;
use crate::rust::types::KeyPair;

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

/// Internal function to generate an X25519 key pair - delegates to core
pub(crate) fn generate_x25519_keypair_internal() -> KeyPair {
    let core_keypair = signal_protocol_core::generate_identity_keypair();
    KeyPair {
        public_key: core_keypair.public_key,
        private_key: core_keypair.private_key,
    }
}

/// Generate an identity key pair for long-term user identification
///
/// Identity keys are long-lived keys that identify a user or device.
/// They are used in the X3DH key exchange protocol and for signing
/// other keys to establish authenticity.
///
/// ## Implementation
/// Uses X25519 (Curve25519 Diffie-Hellman) for key agreement operations.
/// This provides 128-bit security level with efficient constant-time operations.
///
/// ## Security Properties
/// - Uses OS-level entropy source (OsRng)
/// - Generates proper Curve25519 scalar/point pair
/// - Public key is valid curve point derived via scalar multiplication
/// - Constant-time operations prevent timing attacks
///
/// ## Usage
/// Each user/device should generate one identity key pair and use it
/// consistently across all communication sessions. The public key
/// can be distributed through a key server or other trusted mechanism.
///
/// ## Returns
/// A `KeyPair` containing the identity public and private keys (32 bytes each)
#[cfg_attr(coverage_nightly, coverage(off))]
#[wasm_bindgen]
pub fn generate_identity_keypair() -> Result<KeyPair, JsValue> {
    log("Generating identity keypair using X25519");
    Ok(generate_x25519_keypair_internal())
}

/// Generate a signed prekey for medium-term use in key exchanges
///
/// Signed prekeys are generated periodically (e.g., weekly) and signed
/// by the identity key to prove authenticity. They are used in the X3DH
/// protocol to establish initial communication.
///
/// ## Implementation
/// Uses X25519 (Curve25519 Diffie-Hellman) for key agreement operations.
///
/// ## Purpose
/// - Provides forward secrecy by rotating regularly
/// - Enables asynchronous key exchange when recipient is offline
/// - Signed by identity key for authenticity verification
///
/// ## Security Properties
/// - Real elliptic curve cryptography (X25519)
/// - Constant-time operations
/// - Proper scalar/point derivation
///
/// ## Returns
/// A `KeyPair` containing the signed prekey public and private keys (32 bytes each)
#[cfg_attr(coverage_nightly, coverage(off))]
#[wasm_bindgen]
pub fn generate_signed_prekey() -> Result<KeyPair, JsValue> {
    log("Generating signed prekey using X25519");
    Ok(generate_x25519_keypair_internal())
}

/// Generate a one-time prekey for single-use in key exchanges
///
/// One-time prekeys provide additional forward secrecy by being used only once.
/// They are consumed during the X3DH key exchange and then discarded,
/// ensuring that compromise of long-term keys doesn't affect past communications.
///
/// ## Implementation
/// Uses X25519 (Curve25519 Diffie-Hellman) for key agreement operations.
///
/// ## Security Benefits
/// - Perfect forward secrecy (used only once)
/// - Prevents replay attacks on key exchanges
/// - Protects against compromise of identity/signed prekeys
/// - Real elliptic curve cryptography
///
/// ## Returns
/// A `KeyPair` containing the one-time prekey public and private keys (32 bytes each)
#[cfg_attr(coverage_nightly, coverage(off))]
#[wasm_bindgen]
pub fn generate_one_time_prekey() -> Result<KeyPair, JsValue> {
    log("Generating one-time prekey using X25519");
    Ok(generate_x25519_keypair_internal())
}

/// Generate an ephemeral key pair for temporary use in key exchanges
///
/// Ephemeral keys are generated fresh for each key exchange session
/// and provide additional forward secrecy. They are never stored
/// long-term and are discarded after the key exchange completes.
///
/// ## Implementation
/// Uses X25519 (Curve25519 Diffie-Hellman) for key agreement operations.
///
/// ## Use Cases
/// - X3DH key exchange initiation
/// - Session-specific entropy
/// - Enhanced forward secrecy guarantees
///
/// ## Security Properties
/// - Real elliptic curve cryptography (X25519)
/// - Constant-time operations
/// - Fresh randomness for each generation
///
/// ## Returns
/// A `KeyPair` containing the ephemeral public and private keys (32 bytes each)
#[cfg_attr(coverage_nightly, coverage(off))]
#[wasm_bindgen]
pub fn generate_ephemeral_keypair() -> Result<KeyPair, JsValue> {
    log("Generating ephemeral keypair using X25519");
    Ok(generate_x25519_keypair_internal())
}

#[cfg(test)]
#[allow(dead_code)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    /// Test that identity keypairs are generated successfully with real X25519
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen_test]
    fn test_generate_identity_keypair() {
        let keypair = generate_identity_keypair().unwrap();

        // Check that keys are the correct length (32 bytes each for X25519)
        assert_eq!(keypair.public_key().length(), 32);
        assert_eq!(keypair.private_key().length(), 32);

        // Verify that the keypair is valid by using it in an ECDH operation
        let keypair2 = generate_identity_keypair().unwrap();

        // Use the keypair in crypto operations to verify it works
        use crate::rust::crypto::x25519_ecdh;
        let shared_secret = x25519_ecdh(
            &keypair.private_key().to_vec(),
            &keypair2.public_key().to_vec()
        );

        // Should succeed and produce a 32-byte shared secret
        assert!(shared_secret.is_ok());
        assert_eq!(shared_secret.unwrap().len(), 32);
    }

    /// Test that multiple keypair generations produce different results
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen_test]
    fn test_keypair_uniqueness() {
        let keypair1 = generate_identity_keypair().unwrap();
        let keypair2 = generate_identity_keypair().unwrap();
        
        // Keys should be different each time
        assert_ne!(keypair1.public_key().to_vec(), keypair2.public_key().to_vec());
        assert_ne!(keypair1.private_key().to_vec(), keypair2.private_key().to_vec());
    }

    /// Test all key generation functions for basic functionality
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen_test]
    fn test_all_key_generation_functions() {
        // Test all key generation functions
        let identity = generate_identity_keypair().unwrap();
        let signed_prekey = generate_signed_prekey().unwrap();
        let one_time_prekey = generate_one_time_prekey().unwrap();
        let ephemeral = generate_ephemeral_keypair().unwrap();
        
        // All should produce valid keypairs
        assert_eq!(identity.public_key().length(), 32);
        assert_eq!(signed_prekey.public_key().length(), 32);
        assert_eq!(one_time_prekey.public_key().length(), 32);
        assert_eq!(ephemeral.public_key().length(), 32);
        
        // All should be unique
        assert_ne!(identity.public_key().to_vec(), signed_prekey.public_key().to_vec());
        assert_ne!(signed_prekey.public_key().to_vec(), one_time_prekey.public_key().to_vec());
        assert_ne!(one_time_prekey.public_key().to_vec(), ephemeral.public_key().to_vec());
    }
}