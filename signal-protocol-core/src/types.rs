//! Core data types for Signal Protocol (no WASM)

#[cfg(not(hax_compilation))]
use serde::{Deserialize, Serialize};

/// A 32-byte X25519 (or, when used as the Ed25519 component of an
/// [`IdentityKeyPair`], a 32-byte Ed25519) keypair.
#[derive(Clone, Debug)]
#[cfg_attr(not(hax_compilation), derive(Serialize, Deserialize))]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

impl KeyPair {
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn private_key(&self) -> &[u8] {
        &self.private_key
    }
}

/// Long-term identity keypair. The Signal Protocol uses Ed25519 for
/// signing the signed prekey and X25519 for the X3DH DH operations
/// involving the identity key. We hold both as independent random
/// 32-byte secrets to avoid the XEdDSA point-conversion subtlety; this
/// matches `libsignal`'s `IdentityKey` separation.
#[derive(Clone, Debug)]
#[cfg_attr(not(hax_compilation), derive(Serialize, Deserialize))]
pub struct IdentityKeyPair {
    /// X25519 keypair used for DH operations (X3DH DH1, DH2, etc.).
    pub x25519: KeyPair,
    /// Ed25519 keypair used to sign the signed prekey.
    pub ed25519: KeyPair,
}

impl IdentityKeyPair {
    pub fn x25519_public(&self) -> &[u8] {
        &self.x25519.public_key
    }

    pub fn x25519_private(&self) -> &[u8] {
        &self.x25519.private_key
    }

    pub fn ed25519_public(&self) -> &[u8] {
        &self.ed25519.public_key
    }

    pub fn ed25519_private(&self) -> &[u8] {
        &self.ed25519.private_key
    }
}

#[derive(Clone, Debug)]
pub struct X3DHResult {
    pub shared_secret: Vec<u8>,
    pub associated_data: Vec<u8>,
}

impl X3DHResult {
    pub fn shared_secret(&self) -> &[u8] {
        &self.shared_secret
    }

    pub fn associated_data(&self) -> &[u8] {
        &self.associated_data
    }
}

#[derive(Clone, Debug)]
pub struct EncryptionResult {
    pub ciphertext: Vec<u8>,
    pub message_key: Vec<u8>,
}

impl EncryptionResult {
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn message_key(&self) -> &[u8] {
        &self.message_key
    }
}
