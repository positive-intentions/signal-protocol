//! Cryptographic key generation for Signal Protocol

use crate::types::{IdentityKeyPair, KeyPair};

#[cfg(feature = "crypto-backend")]
use ed25519_dalek::SigningKey as EdSigningKey;

#[cfg(feature = "crypto-backend")]
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

#[cfg(feature = "crypto-backend")]
use rand::RngCore;

/// Generate a fresh X25519 keypair. Used for ephemeral keys, signed
/// prekeys, one-time prekeys, and the X25519 component of an
/// [`IdentityKeyPair`].
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

/// Generate a fresh Ed25519 keypair. Used only for the Ed25519 component
/// of an [`IdentityKeyPair`].
#[cfg(feature = "crypto-backend")]
pub fn generate_ed25519_keypair_internal() -> KeyPair {
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);

    let signing_key = EdSigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    KeyPair {
        public_key: verifying_key.to_bytes().to_vec(),
        private_key: signing_key.to_bytes().to_vec(),
    }
}

#[cfg(not(feature = "crypto-backend"))]
#[hax_lib::fstar::replace_body(
    r#"let sk = AbstractCrypto.generate_private_key () in
    let pk = AbstractCrypto.public_key_of_private sk in
    { f_public_key = AbstractCrypto.bytes_to_vec pk; f_private_key = AbstractCrypto.bytes_to_vec sk }"#
)]
pub fn generate_ed25519_keypair_internal() -> KeyPair {
    KeyPair {
        public_key: vec![0u8; 32],
        private_key: vec![0u8; 32],
    }
}

/// Generate a long-term identity keypair: an X25519 keypair (used in
/// X3DH DH operations) and an Ed25519 keypair (used to sign the signed
/// prekey). Both are 32-byte secrets sampled independently from the OS
/// RNG.
#[hax_lib::include]
pub fn generate_identity_keypair() -> IdentityKeyPair {
    IdentityKeyPair {
        x25519: generate_x25519_keypair_internal(),
        ed25519: generate_ed25519_keypair_internal(),
    }
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

/// Generate a fresh X25519 keypair for the Double Ratchet's DH ratchet
/// step. Returns a plain X25519 keypair (NOT an [`IdentityKeyPair`]),
/// matching `Spec.DoubleRatchet.dh_ratchet_step`.
#[hax_lib::include]
pub fn generate_dh_ratchet_keypair() -> KeyPair {
    generate_x25519_keypair_internal()
}
