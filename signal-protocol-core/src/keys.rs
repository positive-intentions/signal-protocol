//! Cryptographic key generation for Signal Protocol

use x25519_dalek::{StaticSecret as X25519StaticSecret, PublicKey as X25519PublicKey};
use rand::RngCore;
use crate::types::KeyPair;

/// Generate an X25519 key pair
pub fn generate_x25519_keypair_internal() -> KeyPair {
    let mut private_key_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut private_key_bytes);

    let static_secret = X25519StaticSecret::from(private_key_bytes);
    let public_key = X25519PublicKey::from(&static_secret);

    KeyPair {
        public_key: public_key.as_bytes().to_vec(),
        private_key: static_secret.to_bytes().to_vec(),
    }
}

/// Generate an identity key pair
pub fn generate_identity_keypair() -> KeyPair {
    generate_x25519_keypair_internal()
}

/// Generate a signed prekey
pub fn generate_signed_prekey() -> KeyPair {
    generate_x25519_keypair_internal()
}

/// Generate a one-time prekey
pub fn generate_one_time_prekey() -> KeyPair {
    generate_x25519_keypair_internal()
}

/// Generate an ephemeral key pair
pub fn generate_ephemeral_keypair() -> KeyPair {
    generate_x25519_keypair_internal()
}
