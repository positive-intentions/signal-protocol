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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_accessors() {
        let kp = KeyPair {
            public_key: vec![1, 2, 3],
            private_key: vec![4, 5, 6],
        };
        assert_eq!(kp.public_key(), &[1, 2, 3]);
        assert_eq!(kp.private_key(), &[4, 5, 6]);
        let _ = format!("{:?}", kp.clone());
    }

    #[test]
    fn x3dh_result_accessors() {
        let r = X3DHResult {
            shared_secret: vec![9],
            associated_data: vec![8],
        };
        assert_eq!(r.shared_secret(), &[9]);
        assert_eq!(r.associated_data(), &[8]);
        let _ = format!("{:?}", r.clone());
    }

    #[test]
    fn encryption_result_accessors() {
        let r = EncryptionResult {
            ciphertext: vec![7],
            message_key: vec![6],
        };
        assert_eq!(r.ciphertext(), &[7]);
        assert_eq!(r.message_key(), &[6]);
        let _ = format!("{:?}", r.clone());
    }
}
