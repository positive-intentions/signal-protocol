//! Signal Protocol Implementation
//! 
//! This module provides a comprehensive implementation of the Signal Protocol
//! for secure end-to-end messaging. The implementation is organized into
//! logical sub-modules for better maintainability and understanding.
//!
//! ## Architecture Overview
//! 
//! The Signal Protocol consists of several key components:
//! - **Key Management**: Generation and handling of cryptographic keys
//! - **X3DH Key Exchange**: Initial key agreement between parties
//! - **Message Encryption**: Secure message encryption and decryption
//! - **Digital Signatures**: Message authentication and integrity
//! - **Utility Functions**: Helper functions for data handling
//!
//! ## Security Features
//! 
//! - Forward secrecy through ephemeral keys
//! - Post-compromise security via key rotation
//! - Authenticated encryption using AES-GCM
//! - HKDF for secure key derivation
//! - Simplified ECDH for demonstrations

pub mod error;
pub mod types;
pub mod keys;
pub mod crypto;
pub mod x3dh;
pub mod messages;
pub mod utils;
pub mod double_ratchet;

// Include tests module for code coverage
#[cfg(test)]
pub mod tests;

// Include WASM tests for complete coverage (test only)
#[cfg(all(target_arch = "wasm32", test))]
pub mod wasm_tests;

// Re-export main types and functions for easy access
pub use error::SignalError;
pub use types::{KeyPair, X3DHResult, EncryptionResult};
pub use keys::{
    generate_identity_keypair,
    generate_signed_prekey,
    generate_one_time_prekey,
    generate_ephemeral_keypair
};
pub use crypto::{sign_data, verify_signature};
pub use x3dh::{x3dh_initiate, x3dh_respond};
pub use messages::{encrypt_message, decrypt_message};
pub use utils::{
    serialize_public_key,
    deserialize_public_key,
    hkdf_derive_key,
    free_keypair,
    free_buffer
};
pub use double_ratchet::{
    DoubleRatchetState,
    DoubleRatchetMessage,
    initialize_double_ratchet,
    double_ratchet_encrypt,
    double_ratchet_decrypt,
    cleanup_skipped_message_keys
};