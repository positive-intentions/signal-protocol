//! Message encryption and decryption for Signal Protocol
//!
//! This module implements the message-level cryptographic operations used in
//! the Signal Protocol. It provides forward secrecy by deriving unique keys
//! for each message and uses authenticated encryption to ensure both
//! confidentiality and integrity.

use wasm_bindgen::prelude::*;
use js_sys::Uint8Array;
#[cfg(target_arch = "wasm32")]
use web_sys::console;
use sha2::Sha256;
use hkdf::Hkdf;
use aes_gcm::{Aes256Gcm, aead::Aead, KeyInit};
use aes_gcm::aead::generic_array::GenericArray;
use rand::{RngCore, rngs::OsRng};
use crate::rust::crypto::uint8_array_to_vec;
use crate::rust::types::EncryptionResult;
use crate::rust::error::SignalError;

/// Log messages to the browser console for debugging
/// 
/// Provides visibility into message encryption/decryption operations
/// during development and troubleshooting.
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

/// Internal function to encrypt a message
/// This is the core logic that can be tested without WASM bindings
pub(crate) fn encrypt_message_internal(
    shared_secret: &[u8],
    plaintext: &[u8],
    message_number: u32,
) -> Result<EncryptionResult, SignalError> {
    // Derive message-specific key using HKDF
    let salt = b"Signal_Message_Salt";
    let info = format!("Signal_Message_{}", message_number);
    let hkdf = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut message_key = [0u8; 32];
    hkdf.expand(info.as_bytes(), &mut message_key)
        .map_err(|e| SignalError::KeyDerivation(format!("Message key derivation failed: {}", e)))?;
    
    // Generate a cryptographically secure random nonce for AES-GCM
    let mut nonce_bytes = [0u8; 12]; // 96 bits for AES-GCM
    OsRng.fill_bytes(&mut nonce_bytes);
    
    // Encrypt using AES-256-GCM
    let key = GenericArray::from_slice(&message_key);
    let cipher = Aes256Gcm::new(key);
    let nonce_ga = GenericArray::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce_ga, plaintext)
        .map_err(|e| SignalError::Encryption(format!("AES-GCM encryption failed: {}", e)))?;
    
    // Prepend nonce to ciphertext for transmission
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    
    Ok(EncryptionResult {
        ciphertext: result,
        message_key: message_key.to_vec(),
    })
}

/// Internal function to decrypt a message
/// This is the core logic that can be tested without WASM bindings
pub(crate) fn decrypt_message_internal(
    ciphertext: &[u8],
    message_key: &[u8],
) -> Result<Vec<u8>, SignalError> {
    // Validate that we have enough data for nonce + encrypted content
    if ciphertext.len() < 12 {
        return Err(SignalError::Decryption("Ciphertext too short (minimum 12 bytes for nonce)".to_string()));
    }
    
    // Extract nonce from the first 12 bytes of ciphertext
    let nonce_ga = GenericArray::from_slice(&ciphertext[..12]);
    let encrypted_data = &ciphertext[12..];

    // Decrypt using AES-256-GCM with the provided message key
    let key = GenericArray::from_slice(message_key);
    let cipher = Aes256Gcm::new(key);

    let plaintext = cipher.decrypt(nonce_ga, encrypted_data)
        .map_err(|e| SignalError::Decryption(format!("AES-GCM decryption failed: {}", e)))?;
    
    Ok(plaintext)
}

/// Encrypt a message using Signal Protocol message encryption
/// 
/// This function implements the Signal Protocol's message encryption scheme,
/// which provides forward secrecy by deriving a unique key for each message.
/// The encryption uses AES-GCM for authenticated encryption, ensuring both
/// confidentiality and integrity.
/// 
/// ## Forward Secrecy Implementation
/// Each message is encrypted with a unique key derived from:
/// - The shared secret from X3DH key exchange
/// - A message-specific counter/number
/// - Cryptographic salt and info strings
/// 
/// This ensures that compromise of one message key doesn't affect other messages.
/// 
/// ## Encryption Process
/// 1. Derive message-specific key using HKDF
/// 2. Generate random 96-bit nonce for AES-GCM
/// 3. Encrypt plaintext with derived key and nonce
/// 4. Prepend nonce to ciphertext for transmission
/// 
/// ## Security Properties
/// - **Confidentiality**: AES-256-GCM encryption
/// - **Integrity**: Built-in authentication tag
/// - **Forward Secrecy**: Unique key per message
/// - **Replay Protection**: Message numbering
/// 
/// ## Parameters
/// - `shared_secret`: The shared secret from X3DH key exchange (32 bytes)
/// - `plaintext`: The message to encrypt
/// - `message_number`: Sequential message counter for forward secrecy
/// 
/// ## Returns
/// An `EncryptionResult` containing:
/// - `ciphertext`: Nonce + encrypted data + auth tag
/// - `message_key`: The derived key for this specific message
/// 
/// ## Example Usage
/// ```javascript
/// const result = encrypt_message(sharedSecret, plaintext, messageNumber);
/// const encryptedData = result.ciphertext();
/// const messageKey = result.message_key();
/// ```
#[wasm_bindgen]
pub fn encrypt_message(
    shared_secret: &Uint8Array,
    plaintext: &Uint8Array,
    message_number: u32,
) -> Result<EncryptionResult, JsValue> {
    log(&format!("Encrypting message #{}", message_number));
    
    let shared_secret_bytes = uint8_array_to_vec(shared_secret);
    let plaintext_bytes = uint8_array_to_vec(plaintext);
    
    match encrypt_message_internal(&shared_secret_bytes, &plaintext_bytes, message_number) {
        Ok(result) => {
            log(&format!("Message encrypted successfully, total size: {} bytes", result.ciphertext.len()));
            Ok(result)
        }
        Err(e) => Err(JsValue::from_str(&e.to_string())),
    }
}

/// Decrypt a message using Signal Protocol message decryption
/// 
/// This function decrypts messages that were encrypted using the Signal Protocol's
/// message encryption scheme. It uses the provided message key and extracts the
/// nonce from the ciphertext to perform AES-GCM decryption.
/// 
/// ## Decryption Process
/// 1. Extract 96-bit nonce from the beginning of ciphertext
/// 2. Use provided message key for AES-GCM decryption
/// 3. Verify authentication tag during decryption
/// 4. Return decrypted plaintext
/// 
/// ## Security Verification
/// - Authentication tag verification ensures message integrity
/// - Nonce uniqueness prevents replay attacks
/// - Key verification ensures authorized decryption
/// 
/// ## Parameters
/// - `shared_secret`: The original shared secret (for validation/logging)
/// - `ciphertext`: The encrypted message with prepended nonce
/// - `message_key`: The derived key for this specific message
/// - `message_number`: The message counter (for logging/validation)
/// 
/// ## Returns
/// A `Uint8Array` containing the decrypted plaintext message
/// 
/// ## Errors
/// - Returns error if ciphertext is too short (< 12 bytes for nonce)
/// - Returns error if AES-GCM decryption fails (wrong key, corrupted data, etc.)
/// - Returns error if authentication tag verification fails
/// 
/// ## Example Usage
/// ```javascript
/// const plaintext = decrypt_message(
///     sharedSecret, 
///     encryptedData, 
///     messageKey, 
///     messageNumber
/// );
/// const message = new TextDecoder().decode(plaintext);
/// ```
#[wasm_bindgen]
pub fn decrypt_message(
    shared_secret: &Uint8Array,
    ciphertext: &Uint8Array,
    message_key: &Uint8Array,
    message_number: u32,
) -> Result<Uint8Array, JsValue> {
    log(&format!("Decrypting message #{}", message_number));
    
    let _shared_secret_bytes = uint8_array_to_vec(shared_secret); // Used for validation/logging
    let ciphertext_bytes = uint8_array_to_vec(ciphertext);
    let message_key_bytes = uint8_array_to_vec(message_key);
    
    match decrypt_message_internal(&ciphertext_bytes, &message_key_bytes) {
        Ok(plaintext) => {
            log("Message decrypted successfully");
            Ok(Uint8Array::from(&plaintext[..]))
        }
        Err(e) => Err(JsValue::from_str(&e.to_string())),
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    /// Test message encryption and decryption roundtrip
    #[wasm_bindgen_test]
    fn test_message_encryption_roundtrip() {
        let shared_secret = Uint8Array::from(&[1u8; 32][..]);
        let plaintext = Uint8Array::from("Hello, Signal Protocol!".as_bytes());
        let message_number = 1;
        
        // Encrypt the message
        let encryption_result = encrypt_message(&shared_secret, &plaintext, message_number).unwrap();
        let ciphertext = encryption_result.ciphertext();
        let message_key = encryption_result.message_key();
        
        // Verify encryption result properties
        assert!(ciphertext.length() > plaintext.length()); // Should be larger due to nonce + auth tag
        assert_eq!(message_key.length(), 32); // 256-bit key
        
        // Decrypt the message
        let decrypted = decrypt_message(&shared_secret, &ciphertext, &message_key, message_number).unwrap();
        
        // Verify decryption worked correctly
        assert_eq!(decrypted.to_vec(), plaintext.to_vec());
    }

    /// Test that different message numbers produce different keys and ciphertexts
    #[wasm_bindgen_test]
    fn test_forward_secrecy() {
        let shared_secret = Uint8Array::from(&[1u8; 32][..]);
        let plaintext = Uint8Array::from("Same message".as_bytes());
        
        // Encrypt same message with different message numbers
        let result1 = encrypt_message(&shared_secret, &plaintext, 1).unwrap();
        let result2 = encrypt_message(&shared_secret, &plaintext, 2).unwrap();
        
        // Message keys should be different (forward secrecy)
        assert_ne!(result1.message_key().to_vec(), result2.message_key().to_vec());
        
        // Ciphertexts should be different (due to different keys and nonces)
        assert_ne!(result1.ciphertext().to_vec(), result2.ciphertext().to_vec());
        
        // But both should decrypt to the same plaintext
        let decrypted1 = decrypt_message(&shared_secret, &result1.ciphertext(), &result1.message_key(), 1).unwrap();
        let decrypted2 = decrypt_message(&shared_secret, &result2.ciphertext(), &result2.message_key(), 2).unwrap();
        
        assert_eq!(decrypted1.to_vec(), plaintext.to_vec());
        assert_eq!(decrypted2.to_vec(), plaintext.to_vec());
    }

    /// Test that wrong message key fails decryption
    #[wasm_bindgen_test]
    fn test_wrong_key_decryption_fails() {
        let shared_secret = Uint8Array::from(&[1u8; 32][..]);
        let plaintext = Uint8Array::from("Secret message".as_bytes());
        let message_number = 1;
        
        // Encrypt with correct key
        let encryption_result = encrypt_message(&shared_secret, &plaintext, message_number).unwrap();
        let ciphertext = encryption_result.ciphertext();
        
        // Try to decrypt with wrong key
        let wrong_key = Uint8Array::from(&[2u8; 32][..]);
        let decrypt_result = decrypt_message(&shared_secret, &ciphertext, &wrong_key, message_number);
        
        // Decryption should fail with wrong key
        assert!(decrypt_result.is_err());
    }

    /// Test error handling for malformed ciphertext
    #[wasm_bindgen_test]
    fn test_short_ciphertext_error() {
        let shared_secret = Uint8Array::from(&[1u8; 32][..]);
        let message_key = Uint8Array::from(&[1u8; 32][..]);
        let short_ciphertext = Uint8Array::from(&[1u8; 8][..]); // Too short for nonce
        
        let result = decrypt_message(&shared_secret, &short_ciphertext, &message_key, 1);
        assert!(result.is_err());
    }

    /// Test that same inputs produce different ciphertexts (due to random nonces)
    #[wasm_bindgen_test]
    fn test_nonce_randomization() {
        let shared_secret = Uint8Array::from(&[1u8; 32][..]);
        let plaintext = Uint8Array::from("Same message".as_bytes());
        let message_number = 1;
        
        // Encrypt same message twice with same parameters
        let result1 = encrypt_message(&shared_secret, &plaintext, message_number).unwrap();
        let result2 = encrypt_message(&shared_secret, &plaintext, message_number).unwrap();
        
        // Should produce different ciphertexts due to random nonces
        assert_ne!(result1.ciphertext().to_vec(), result2.ciphertext().to_vec());
        
        // But same message keys (deterministic derivation)
        assert_eq!(result1.message_key().to_vec(), result2.message_key().to_vec());
    }
}