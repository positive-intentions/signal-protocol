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

pub mod crypto;
pub mod double_ratchet;
pub mod error;
pub mod keys;
pub mod messages;
pub mod types;
pub mod utils;
pub mod x3dh;

// Include tests module for code coverage
#[cfg(test)]
pub mod tests;

// Include WASM tests for complete coverage (test only)
#[cfg(all(target_arch = "wasm32", test))]
pub mod wasm_tests;

// Re-export main types and functions for easy access
pub use crypto::{sign_data, verify_signature};
pub use double_ratchet::{
    cleanup_skipped_message_keys, double_ratchet_decrypt, double_ratchet_encrypt,
    initialize_double_ratchet, DoubleRatchetMessage, DoubleRatchetState,
};
pub use error::SignalError;
pub use keys::{
    generate_ephemeral_keypair, generate_identity_keypair, generate_one_time_prekey,
    generate_signed_prekey,
};
pub use messages::{decrypt_message, encrypt_message};
pub use types::{EncryptionResult, KeyPair, X3DHResult};
pub use utils::{
    deserialize_public_key, free_buffer, free_keypair, hkdf_derive_key, serialize_public_key,
};
pub use x3dh::{x3dh_initiate, x3dh_respond};
