//! Core data types for Signal Protocol
//!
//! This module defines the main data structures used throughout the Signal Protocol
//! implementation. All types are designed to work seamlessly with WebAssembly
//! and provide efficient JavaScript interoperability.

use wasm_bindgen::prelude::*;
use js_sys::Uint8Array;
use serde::{Serialize, Deserialize};

/// Cryptographic key pair structure
/// 
/// Represents a public/private key pair used in the Signal Protocol.
/// The keys are stored as byte vectors internally but exposed to JavaScript
/// as Uint8Array objects for compatibility.
/// 
/// ## Security Note
/// Private keys should be handled with extreme care and never exposed
/// in logs or transmitted over insecure channels.
#[wasm_bindgen]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyPair {
    /// Public key bytes - safe to share with other parties
    #[wasm_bindgen(skip)]
    pub public_key: Vec<u8>,
    
    /// Private key bytes - must be kept secret and secure
    #[wasm_bindgen(skip)]
    pub private_key: Vec<u8>,
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[wasm_bindgen]
impl KeyPair {
    /// Get the public key as a JavaScript Uint8Array
    /// 
    /// The public key can be safely shared with other parties for
    /// encryption, signature verification, or key agreement protocols.
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Uint8Array {
        Uint8Array::from(&self.public_key[..])
    }

    /// Get the private key as a JavaScript Uint8Array
    /// 
    /// ⚠️ **WARNING**: Private keys must be handled securely.
    /// Only access this when absolutely necessary for cryptographic operations.
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen(getter)]
    pub fn private_key(&self) -> Uint8Array {
        Uint8Array::from(&self.private_key[..])
    }
}

/// Result of X3DH key exchange protocol
/// 
/// Contains the shared secret and associated data produced by the X3DH
/// key agreement protocol. This data is used to initialize secure
/// communication channels between two parties.
/// 
/// ## X3DH Protocol
/// The Extended Triple Diffie-Hellman (X3DH) is Signal's key agreement
/// protocol that provides mutual authentication and forward secrecy.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct X3DHResult {
    /// The derived shared secret for secure communication
    /// This secret is used to derive message encryption keys
    #[wasm_bindgen(skip)]
    pub shared_secret: Vec<u8>,
    
    /// Associated data for additional context/authentication
    /// Can be used for protocol versioning or additional metadata
    #[wasm_bindgen(skip)]
    pub associated_data: Vec<u8>,
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[wasm_bindgen]
impl X3DHResult {
    /// Get the shared secret as a JavaScript Uint8Array
    /// 
    /// This secret should be used immediately for key derivation and
    /// then securely wiped from memory when no longer needed.
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen(getter)]
    pub fn shared_secret(&self) -> Uint8Array {
        Uint8Array::from(&self.shared_secret[..])
    }

    /// Get the associated data as a JavaScript Uint8Array
    /// 
    /// Associated data provides additional context for the key exchange
    /// and can be used for protocol versioning or authentication.
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen(getter)]
    pub fn associated_data(&self) -> Uint8Array {
        Uint8Array::from(&self.associated_data[..])
    }
}

/// Result of message encryption operation
/// 
/// Contains both the encrypted ciphertext and the derived message key.
/// The message key can be stored for future decryption operations,
/// enabling asynchronous message processing.
/// 
/// ## Forward Secrecy
/// Each message uses a unique derived key, ensuring that compromise
/// of one message key doesn't affect the security of other messages.
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct EncryptionResult {
    /// The encrypted message data with authentication tag
    /// Includes the AES-GCM nonce prepended to the ciphertext
    #[wasm_bindgen(skip)]
    pub ciphertext: Vec<u8>,
    
    /// The derived message key used for this specific message
    /// Can be stored separately for later decryption
    #[wasm_bindgen(skip)]
    pub message_key: Vec<u8>,
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[wasm_bindgen]
impl EncryptionResult {
    /// Get the ciphertext as a JavaScript Uint8Array
    /// 
    /// The ciphertext includes the nonce and authentication tag,
    /// making it self-contained for transmission and storage.
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Uint8Array {
        Uint8Array::from(&self.ciphertext[..])
    }

    /// Get the message key as a JavaScript Uint8Array
    /// 
    /// This key is required for decryption and should be stored
    /// securely alongside the ciphertext if needed for later access.
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[wasm_bindgen(getter)]
    pub fn message_key(&self) -> Uint8Array {
        Uint8Array::from(&self.message_key[..])
    }
}