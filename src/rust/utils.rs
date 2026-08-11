//! Utility functions for Signal Protocol implementation
//!
//! This module provides helper functions for data serialization, key management,
//! memory cleanup, and other common operations used throughout the Signal Protocol
//! implementation.

use wasm_bindgen::prelude::*;
use js_sys::Uint8Array;
#[cfg(target_arch = "wasm32")]
use web_sys::console;
use sha2::Sha256;
use hkdf::Hkdf;
use crate::rust::crypto::uint8_array_to_vec;
use crate::rust::types::KeyPair;

/// Log messages to the browser console for debugging
/// 
/// Provides visibility into utility operations during development
/// and helps trace data transformations and memory operations.
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) fn log(s: &str) {
    #[cfg(target_arch = "wasm32")]
    {
        console::log_1(&JsValue::from_str(s));
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        eprintln!("{}", s);
    }
}

/// Internal function to serialize a public key (native version)
/// 
/// This is the core serialization logic that can be tested without WASM types.
/// Adds a version byte (0x05) to indicate compressed point format.
pub(crate) fn serialize_public_key_internal(public_key: &[u8]) -> Result<Vec<u8>, String> {
    if public_key.len() != 32 {
        return Err("Public key must be 32 bytes".to_string());
    }
    
    let mut serialized = Vec::with_capacity(33);
    serialized.push(0x05); // Version byte for compressed point
    serialized.extend_from_slice(public_key);
    Ok(serialized)
}

/// Internal function to deserialize a public key (native version) 
/// 
/// This is the core deserialization logic that can be tested without WASM types.
/// Removes the version byte and validates the format.
pub(crate) fn deserialize_public_key_internal(serialized_key: &[u8]) -> Result<Vec<u8>, String> {
    if serialized_key.len() != 33 {
        return Err("Serialized key must be 33 bytes".to_string());
    }
    
    if serialized_key[0] != 0x05 {
        return Err("Invalid key version byte".to_string());
    }
    
    Ok(serialized_key[1..].to_vec())
}

/// Internal function for HKDF key derivation (native version)
/// 
/// This is the core HKDF logic that can be tested without WASM types.
pub(crate) fn hkdf_derive_key_internal(
    input_key: &[u8],
    salt: &[u8], 
    info: &[u8],
    output_length: usize
) -> Result<Vec<u8>, String> {
    // Validate output length (HKDF has theoretical limits)
    if output_length == 0 {
        return Err("Output length must be greater than 0".to_string());
    }
    
    if output_length > 255 * 32 { // SHA-256 HMAC length limit
        return Err("Output length too large for HKDF-SHA256".to_string());
    }
    
    // Perform HKDF key derivation
    let hkdf = if salt.is_empty() {
        Hkdf::<Sha256>::new(None, input_key)
    } else {
        Hkdf::<Sha256>::new(Some(salt), input_key)
    };
    
    let mut output = vec![0u8; output_length];
    // Length is validated above against the HKDF-SHA256 expand limit.
    hkdf.expand(info, &mut output)
        .expect("HKDF expand within validated length cannot fail");

    Ok(output)
}

/// Serialize a public key for transmission or storage
/// 
/// This function prepares a public key for transmission over a network or
/// storage in a database by adding protocol metadata. In the Signal Protocol,
/// public keys are often serialized with version bytes to ensure compatibility
/// and proper parsing.
/// 
/// ## Serialization Format
/// - Version byte (0x05): Indicates compressed point format
/// - Key data: The raw 32-byte public key
/// - Total size: 33 bytes
/// 
/// ## Use Cases
/// - Transmitting public keys in key exchange messages
/// - Storing public keys in databases or key servers
/// - Including public keys in signed prekey bundles
/// - Protocol message headers
/// 
/// ## Parameters
/// - `public_key`: The 32-byte public key to serialize
/// 
/// ## Returns
/// A 33-byte serialized key with version prefix
/// 
/// ## Errors
/// - Returns error if public key is not exactly 32 bytes
/// 
/// ## Example Usage
/// ```javascript
/// const serialized = serialize_public_key(publicKey);
/// // Send serialized key over network or store in database
/// ```
#[cfg_attr(coverage_nightly, coverage(off))]
#[wasm_bindgen]
pub fn serialize_public_key(public_key: &Uint8Array) -> Result<Uint8Array, JsValue> {
    log("Serializing public key for transmission");
    
    let key_bytes = uint8_array_to_vec(public_key);
    
    match serialize_public_key_internal(&key_bytes) {
        Ok(serialized) => {
            log(&format!("Public key serialized: {} bytes total", serialized.len()));
            Ok(Uint8Array::from(&serialized[..]))
        },
        Err(error) => Err(JsValue::from_str(&error))
    }
}

/// Deserialize a public key from its serialized format
/// 
/// This function extracts a public key from its serialized representation,
/// performing validation checks to ensure the data is well-formed and
/// compatible with the expected protocol version.
/// 
/// ## Deserialization Process
/// 1. Validate total length (must be 33 bytes)
/// 2. Check version byte (must be 0x05)
/// 3. Extract 32-byte key data
/// 4. Return raw key bytes
/// 
/// ## Security Considerations
/// - Validates data integrity before processing
/// - Rejects malformed or unexpected formats
/// - Prevents buffer overflow attacks
/// - Ensures protocol compatibility
/// 
/// ## Parameters
/// - `serialized_key`: The 33-byte serialized key with version prefix
/// 
/// ## Returns
/// The original 32-byte public key
/// 
/// ## Errors
/// - Returns error if serialized key is not 33 bytes
/// - Returns error if version byte is not 0x05
/// - Returns error for any malformed input
/// 
/// ## Example Usage
/// ```javascript
/// const publicKey = deserialize_public_key(receivedData);
/// // Use public key for cryptographic operations
/// ```
#[cfg_attr(coverage_nightly, coverage(off))]
#[wasm_bindgen]
pub fn deserialize_public_key(serialized_key: &Uint8Array) -> Result<Uint8Array, JsValue> {
    log("Deserializing public key from transmission format");
    
    let serialized_bytes = uint8_array_to_vec(serialized_key);
    
    match deserialize_public_key_internal(&serialized_bytes) {
        Ok(key_data) => {
            log(&format!("Public key deserialized successfully: {} bytes", key_data.len()));
            Ok(Uint8Array::from(&key_data[..]))
        },
        Err(error) => Err(JsValue::from_str(&error))
    }
}

/// Derive cryptographic keys using HKDF (HMAC-based Key Derivation Function)
/// 
/// HKDF is the standard key derivation function used in the Signal Protocol
/// for expanding shared secrets into specific-purpose keys. It provides
/// cryptographic strength and domain separation for different key uses.
/// 
/// ## HKDF Algorithm
/// HKDF operates in two phases:
/// 1. **Extract**: Uses HMAC to extract pseudorandom key from input material
/// 2. **Expand**: Expands the pseudorandom key to desired output length
/// 
/// ## Security Properties
/// - **Entropy preservation**: Maintains entropy from input material
/// - **Domain separation**: Different info strings produce independent keys
/// - **Length flexibility**: Can produce keys of any required length
/// - **Cryptographic strength**: Based on proven HMAC construction
/// 
/// ## Use Cases
/// - Deriving message keys from shared secrets
/// - Creating separate encryption and authentication keys
/// - Key rotation and forward secrecy
/// - Protocol-specific key derivation
/// 
/// ## Parameters
/// - `input_key_material`: The source entropy (e.g., ECDH shared secret)
/// - `salt`: Optional salt for additional security (can be empty)
/// - `info`: Context-specific information for domain separation
/// - `output_length`: Desired length of derived key in bytes
/// 
/// ## Returns
/// A derived key of the specified length
/// 
/// ## Errors
/// - Returns error if HKDF expansion fails
/// - Returns error for invalid output lengths
/// 
/// ## Example Usage
/// ```javascript
/// const messageKey = hkdf_derive_key(
///     sharedSecret,
///     salt,
///     new TextEncoder().encode("Signal_Message_Key"),
///     32
/// );
/// ```
#[cfg_attr(coverage_nightly, coverage(off))]
#[wasm_bindgen]
pub fn hkdf_derive_key(
    input_key_material: &Uint8Array,
    salt: &Uint8Array,
    info: &Uint8Array,
    output_length: usize,
) -> Result<Uint8Array, JsValue> {
    log(&format!("Deriving key with HKDF: output length {} bytes", output_length));
    
    let ikm = uint8_array_to_vec(input_key_material);
    let salt_bytes = uint8_array_to_vec(salt);
    let info_bytes = uint8_array_to_vec(info);
    
    match hkdf_derive_key_internal(&ikm, &salt_bytes, &info_bytes, output_length) {
        Ok(output) => {
            log(&format!("HKDF key derivation completed: {} bytes generated", output.len()));
            Ok(Uint8Array::from(&output[..]))
        },
        Err(error) => Err(JsValue::from_str(&error))
    }
}

/// Free memory associated with a KeyPair (placeholder for manual memory management)
/// 
/// In Rust, memory management is automatic through RAII (Resource Acquisition Is Initialization).
/// This function exists for API compatibility with other implementations that might require
/// explicit memory management (e.g., C implementations).
/// 
/// ## Memory Management in Rust
/// - Rust automatically deallocates memory when variables go out of scope
/// - No manual memory management is typically required
/// - This function serves as a no-op placeholder for API compatibility
/// 
/// ## Use Cases
/// - API compatibility with C-based implementations
/// - Explicit documentation of cleanup points
/// - Future integration with custom allocators
/// - Testing memory management flows
/// 
/// ## Parameters
/// - `_keypair`: The KeyPair to "free" (parameter is ignored)
/// 
/// ## Example Usage
/// ```javascript
/// // Optional explicit cleanup (not required in Rust/WASM)
/// free_keypair(keyPair);
/// ```
#[cfg_attr(coverage_nightly, coverage(off))]
#[wasm_bindgen]
pub fn free_keypair(_keypair: &KeyPair) {
    log("KeyPair memory cleanup requested (automatic in Rust)");
    // In Rust, memory is automatically managed through RAII
    // This function exists for API compatibility with other implementations
}

/// Free memory associated with a buffer (placeholder for manual memory management)
/// 
/// Similar to `free_keypair`, this function exists for API compatibility.
/// Rust's automatic memory management handles buffer cleanup automatically
/// when the buffer goes out of scope.
/// 
/// ## Buffer Management
/// - Uint8Array data is automatically managed by the JavaScript engine
/// - Rust Vec<u8> data is automatically deallocated when dropped
/// - No manual intervention is required in typical usage
/// 
/// ## Parameters
/// - `_buffer`: The buffer to "free" (parameter is ignored)
/// 
/// ## Example Usage
/// ```javascript
/// // Optional explicit cleanup (not required in Rust/WASM)
/// free_buffer(buffer);
/// ```
#[cfg_attr(coverage_nightly, coverage(off))]
#[wasm_bindgen]
pub fn free_buffer(_buffer: &Uint8Array) {
    log("Buffer memory cleanup requested (automatic in Rust/WASM)");
    // Memory cleanup is handled automatically by Rust and the JavaScript engine
    // This function exists for API compatibility
}

#[cfg(test)]
#[allow(dead_code)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    /// Test public key serialization and deserialization roundtrip
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen_test]
    fn test_key_serialization_roundtrip() {
        let original_key = Uint8Array::from(&[1u8; 32][..]);
        
        // Serialize the key
        let serialized = serialize_public_key(&original_key).unwrap();
        assert_eq!(serialized.length(), 33); // 32 bytes + 1 version byte
        assert_eq!(serialized.get_index(0), 0x05); // Version byte
        
        // Deserialize the key
        let deserialized = deserialize_public_key(&serialized).unwrap();
        assert_eq!(deserialized.length(), 32);
        assert_eq!(deserialized.to_vec(), original_key.to_vec());
    }

    /// Test key serialization error handling
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen_test]
    fn test_key_serialization_errors() {
        // Test with wrong key size
        let wrong_size_key = Uint8Array::from(&[1u8; 16][..]);
        let result = serialize_public_key(&wrong_size_key);
        assert!(result.is_err());
        
        // Test deserialization with wrong size
        let wrong_size_serialized = Uint8Array::from(&[0x05, 1, 2, 3][..]);
        let result = deserialize_public_key(&wrong_size_serialized);
        assert!(result.is_err());
        
        // Test deserialization with wrong version
        let mut wrong_version = vec![0x99]; // Wrong version byte
        wrong_version.extend_from_slice(&[1u8; 32]);
        let wrong_version_serialized = Uint8Array::from(&wrong_version[..]);
        let result = deserialize_public_key(&wrong_version_serialized);
        assert!(result.is_err());
    }

    /// Test HKDF key derivation
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen_test]
    fn test_hkdf_derivation() {
        let input_material = Uint8Array::from(&[1u8; 32][..]);
        let salt = Uint8Array::from("test_salt".as_bytes());
        let info = Uint8Array::from("test_info".as_bytes());
        
        // Derive a 32-byte key
        let derived_key = hkdf_derive_key(&input_material, &salt, &info, 32).unwrap();
        assert_eq!(derived_key.length(), 32);
        
        // Derive a different length key
        let derived_key_64 = hkdf_derive_key(&input_material, &salt, &info, 64).unwrap();
        assert_eq!(derived_key_64.length(), 64);
        
        // Same inputs should produce same outputs
        let derived_key2 = hkdf_derive_key(&input_material, &salt, &info, 32).unwrap();
        assert_eq!(derived_key.to_vec(), derived_key2.to_vec());
        
        // Different info should produce different outputs
        let different_info = Uint8Array::from("different_info".as_bytes());
        let different_key = hkdf_derive_key(&input_material, &salt, &different_info, 32).unwrap();
        assert_ne!(derived_key.to_vec(), different_key.to_vec());
    }

    /// Test HKDF with empty salt
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen_test]
    fn test_hkdf_empty_salt() {
        let input_material = Uint8Array::from(&[1u8; 32][..]);
        let empty_salt = Uint8Array::new_with_length(0);
        let info = Uint8Array::from("test_info".as_bytes());
        
        let derived_key = hkdf_derive_key(&input_material, &empty_salt, &info, 32).unwrap();
        assert_eq!(derived_key.length(), 32);
    }

    /// Test HKDF error conditions
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen_test]
    fn test_hkdf_errors() {
        let input_material = Uint8Array::from(&[1u8; 32][..]);
        let salt = Uint8Array::from("salt".as_bytes());
        let info = Uint8Array::from("info".as_bytes());
        
        // Test zero output length
        let result = hkdf_derive_key(&input_material, &salt, &info, 0);
        assert!(result.is_err());
        
        // Test excessive output length
        let result = hkdf_derive_key(&input_material, &salt, &info, 10000);
        assert!(result.is_err());
    }

    /// Test memory management functions (they should not panic)
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen_test]
    fn test_memory_management_functions() {
        use crate::rust::keys::generate_identity_keypair;
        
        // Test keypair cleanup
        let keypair = generate_identity_keypair().unwrap();
        free_keypair(&keypair); // Should not panic
        
        // Test buffer cleanup
        let buffer = Uint8Array::from(&[1u8; 32][..]);
        free_buffer(&buffer); // Should not panic
    }
}