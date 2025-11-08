//! Signal Protocol WebAssembly Implementation
//!
//! This is a comprehensive implementation of the Signal Protocol compiled to WebAssembly
//! for use in web browsers and Node.js applications. The implementation provides all
//! core Signal Protocol functionality including key generation, X3DH key exchange,
//! and message encryption with forward secrecy.
//!
//! ## Features
//!
//! - **Complete Signal Protocol Implementation**
//! - **WebAssembly Compiled** for high performance
//! - **Browser and Node.js Compatible**
//! - **Forward Secrecy** through ephemeral keys
//! - **Authenticated Encryption** using AES-GCM
//! - **Key Derivation** using HKDF-SHA256
//! - **Comprehensive Testing** with unit tests
//!
//! ## Architecture
//!
//! The implementation is organized into logical modules:
//! - `error`: Error types and handling
//! - `types`: Core data structures
//! - `keys`: Key generation functions  
//! - `crypto`: Digital signatures and ECDH
//! - `x3dh`: X3DH key exchange protocol
//! - `messages`: Message encryption/decryption
//! - `utils`: Utility functions and helpers

#[cfg(not(test))]
use wasm_bindgen::prelude::*;
#[cfg(not(test))]
use web_sys::console;

// Import modular implementation
pub mod rust;

// Re-export all public types and functions for JavaScript access
pub use rust::{
    SignalError,
    KeyPair, X3DHResult, EncryptionResult,
    generate_identity_keypair, generate_signed_prekey, 
    generate_one_time_prekey, generate_ephemeral_keypair,
    sign_data, verify_signature,
    x3dh_initiate, x3dh_respond,
    encrypt_message, decrypt_message,
    serialize_public_key, deserialize_public_key,
    hkdf_derive_key, free_keypair, free_buffer
};


/// Initialize the WASM module
/// 
/// This function is automatically called when the WASM module is loaded.
/// It sets up error handling and logging for better debugging experience.
#[wasm_bindgen(start)]
#[cfg(not(test))]
pub fn main() {
    // Log module initialization to browser console
    console::log_1(&JsValue::from_str("Signal Protocol WASM module initialized"));
    
    // Set up panic hook for better error messages in development
    console_error_panic_hook::set_once();
}

/// Initialize the WASM module for tests
/// 
/// This is a separate test-only initialization to avoid main symbol conflicts.
#[cfg(test)]
pub fn init_for_test() {
    console_error_panic_hook::set_once();
}