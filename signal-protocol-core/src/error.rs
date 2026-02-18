//! Error handling for Signal Protocol core

use thiserror::Error;

/// Comprehensive error types for Signal Protocol operations
#[derive(Error, Debug)]
pub enum SignalError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Signature verification failed: {0}")]
    SignatureVerification(String),

    #[error("Key exchange failed: {0}")]
    KeyExchange(String),

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("Serialization failed: {0}")]
    Serialization(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}
