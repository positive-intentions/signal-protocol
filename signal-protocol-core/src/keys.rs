//! Cryptographic key generation for Signal Protocol

use crate::types::KeyPair;

#[cfg(feature = "crypto-backend")]
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

#[cfg(feature = "crypto-backend")]
use rand::RngCore;

#[cfg(feature = "crypto-backend")]
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

#[cfg(not(feature = "crypto-backend"))]
#[hax_lib::fstar::replace_body(
    r#"let sk = AbstractCrypto.generate_private_key () in
    let pk = AbstractCrypto.public_key_of_private sk in
    { f_public_key = AbstractCrypto.bytes_to_vec pk; f_private_key = AbstractCrypto.bytes_to_vec sk }"#
)]
pub fn generate_x25519_keypair_internal() -> KeyPair {
    KeyPair {
        public_key: vec![0u8; 32],
        private_key: vec![0u8; 32],
    }
}

#[hax_lib::include]
pub fn generate_identity_keypair() -> KeyPair {
    generate_x25519_keypair_internal()
}

#[hax_lib::include]
pub fn generate_signed_prekey() -> KeyPair {
    generate_x25519_keypair_internal()
}

#[hax_lib::include]
pub fn generate_one_time_prekey() -> KeyPair {
    generate_x25519_keypair_internal()
}

#[hax_lib::include]
pub fn generate_ephemeral_keypair() -> KeyPair {
    generate_x25519_keypair_internal()
}
