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

/// Legacy separate Ed25519 signing keypair (deprecated for Signal SPK path).
/// Prefer XEdDSA on the identity key via [`sign_prekey`] / [`verify_signed_prekey`].
#[cfg(feature = "crypto-backend")]
pub fn generate_sign_keypair() -> KeyPair {
    use ed25519_dalek::SigningKey;
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    KeyPair {
        public_key: signing_key.verifying_key().to_bytes().to_vec(),
        private_key: signing_key.to_bytes().to_vec(),
    }
}

#[cfg(not(feature = "crypto-backend"))]
pub fn generate_sign_keypair() -> KeyPair {
    KeyPair {
        public_key: vec![0u8; 32],
        private_key: vec![0u8; 32],
    }
}

/// Sign the 32-byte signed-prekey public key with the **identity** X25519 private key (XEdDSA).
pub fn sign_prekey(
    identity_private: &[u8],
    signed_prekey_public: &[u8],
) -> Result<Vec<u8>, crate::SignalError> {
    if signed_prekey_public.len() != 32 {
        return Err(crate::SignalError::InvalidInput(
            "Signed prekey public key must be 32 bytes".to_string(),
        ));
    }
    crate::xeddsa::xeddsa_sign(identity_private, signed_prekey_public)
}

/// Verify a signed-prekey signature with the **identity** X25519 public key (XEdDSA).
pub fn verify_signed_prekey(
    identity_public: &[u8],
    signed_prekey_public: &[u8],
    signature: &[u8],
) -> Result<(), crate::SignalError> {
    if signed_prekey_public.len() != 32 {
        return Err(crate::SignalError::InvalidInput(
            "Signed prekey public key must be 32 bytes".to_string(),
        ));
    }
    let ok = crate::xeddsa::xeddsa_verify(identity_public, signature, signed_prekey_public)?;
    if ok {
        Ok(())
    } else {
        Err(crate::SignalError::SignatureVerification(
            "signal signed prekey".into(),
        ))
    }
}

/// Edwards form of an X25519 identity public key (for wire bundles that publish a sign public).
pub fn identity_sign_public(identity_public: &[u8]) -> Result<Vec<u8>, crate::SignalError> {
    Ok(crate::xeddsa::montgomery_to_edwards_public(identity_public)?.to_vec())
}

#[cfg(all(test, feature = "crypto-backend"))]
mod tests {
    use super::*;

    #[test]
    fn all_generators_produce_32_byte_keys() {
        for kp in [
            generate_identity_keypair(),
            generate_signed_prekey(),
            generate_one_time_prekey(),
            generate_ephemeral_keypair(),
            generate_x25519_keypair_internal(),
        ] {
            assert_eq!(kp.public_key.len(), 32);
            assert_eq!(kp.private_key.len(), 32);
            assert_ne!(kp.public_key, kp.private_key);
        }
    }

    #[test]
    fn generators_are_unique() {
        let a = generate_identity_keypair();
        let b = generate_identity_keypair();
        assert_ne!(a.private_key, b.private_key);
        assert_ne!(a.public_key, b.public_key);
    }

    #[test]
    fn sign_prekey_with_identity_xeddsa() {
        let id = generate_identity_keypair();
        let spk = generate_signed_prekey();
        let sig = sign_prekey(&id.private_key, &spk.public_key).unwrap();
        verify_signed_prekey(&id.public_key, &spk.public_key, &sig).unwrap();
        assert!(verify_signed_prekey(&id.public_key, &spk.public_key, &[0u8; 64]).is_err());
    }
}
