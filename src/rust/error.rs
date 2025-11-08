//! Error handling for Signal Protocol implementation
//!
//! This module defines all possible errors that can occur during Signal Protocol
//! operations. Using the `thiserror` crate provides ergonomic error handling
//! with automatic implementations of common traits.

use wasm_bindgen::prelude::*;
use thiserror::Error;

/// Comprehensive error types for Signal Protocol operations
/// 
/// Each error variant represents a different category of failure that can occur
/// during cryptographic operations. The error messages provide context about
/// what went wrong to aid in debugging.
#[derive(Error, Debug)]
pub enum SignalError {
    /// Errors during key generation processes
    /// 
    /// This can occur due to insufficient entropy, hardware failures,
    /// or other issues with the random number generator.
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),
    
    /// Digital signature verification failures
    /// 
    /// Thrown when a signature doesn't match the expected value for
    /// the given data and public key combination.
    #[error("Signature verification failed: {0}")]
    SignatureVerification(String),
    
    /// X3DH key exchange protocol failures
    /// 
    /// Can occur due to invalid keys, protocol violations, or
    /// cryptographic computation errors during key agreement.
    #[error("Key exchange failed: {0}")]
    KeyExchange(String),
    
    /// Message encryption failures
    /// 
    /// Usually indicates issues with key derivation, AES-GCM encryption,
    /// or insufficient randomness for nonce generation.
    #[error("Encryption failed: {0}")]
    Encryption(String),
    
    /// Message decryption failures
    /// 
    /// Can result from corrupted ciphertext, wrong keys, tampered data,
    /// or authentication tag verification failures.
    #[error("Decryption failed: {0}")]
    Decryption(String),
    
    /// Key derivation function (HKDF) failures
    /// 
    /// Occurs when HKDF operations fail due to invalid parameters
    /// or insufficient input key material.
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),
    
    /// Serialization and deserialization errors
    /// 
    /// Happens when converting between different data formats fails,
    /// such as binary to JSON or vice versa.
    #[error("Serialization failed: {0}")]
    Serialization(String),
    
    /// Invalid input parameter errors
    /// 
    /// Thrown when function parameters don't meet requirements,
    /// such as wrong key sizes or invalid data formats.
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

/// Convert SignalError to JavaScript-compatible JsValue
/// 
/// This implementation allows Rust errors to be properly propagated
/// to JavaScript code when using WASM bindings. The error message
/// is preserved for debugging purposes.
impl Into<JsValue> for SignalError {
    fn into(self) -> JsValue {
        JsValue::from_str(&self.to_string())
    }
}