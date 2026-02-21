//! Core data types for Signal Protocol (no WASM)

#[cfg(not(hax_compilation))]
use serde::{Deserialize, Serialize};

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
