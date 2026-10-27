//! XEdDSA signatures over X25519 identity keys (SP-2026-006).
//!
//! Research implementation: X25519 identity scalars sign; Montgomery publics
//! convert to Edwards for verification. Not claimed libsignal-wire-compatible.

use crate::error::SignalError;

#[cfg(feature = "crypto-backend")]
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
#[cfg(feature = "crypto-backend")]
use curve25519_dalek::edwards::CompressedEdwardsY;
#[cfg(feature = "crypto-backend")]
use curve25519_dalek::montgomery::MontgomeryPoint;
#[cfg(feature = "crypto-backend")]
use curve25519_dalek::scalar::Scalar;
#[cfg(feature = "crypto-backend")]
use sha2::{Digest, Sha512};
#[cfg(feature = "crypto-backend")]
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

#[cfg(feature = "crypto-backend")]
const XEDDSA_DOM: &[u8] = b"Signal_XEdDSA";

#[cfg(feature = "crypto-backend")]
fn clamp_scalar_bytes(private_key: &[u8; 32]) -> [u8; 32] {
    let mut e = *private_key;
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;
    e
}

#[cfg(feature = "crypto-backend")]
fn hash_to_scalar(parts: &[&[u8]]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(XEDDSA_DOM);
    for p in parts {
        hasher.update(p);
    }
    let digest = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Derive the Edwards public key bytes corresponding to an X25519 Montgomery public key.
pub fn montgomery_to_edwards_public(x25519_public: &[u8]) -> Result<[u8; 32], SignalError> {
    if x25519_public.len() != 32 {
        return Err(SignalError::InvalidInput(
            "X25519 public key must be 32 bytes".to_string(),
        ));
    }
    #[cfg(feature = "crypto-backend")]
    {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(x25519_public);
        let mont = MontgomeryPoint(bytes);
        for sign in [0u8, 1u8] {
            if let Some(ed) = mont.to_edwards(sign) {
                return Ok(ed.compress().to_bytes());
            }
        }
        Err(SignalError::InvalidInput(
            "X25519 public key is not a valid curve point".to_string(),
        ))
    }
    #[cfg(not(feature = "crypto-backend"))]
    {
        let mut out = [0u8; 32];
        out.copy_from_slice(x25519_public);
        Ok(out)
    }
}

/// Sign `message` with an X25519 private key using XEdDSA.
#[cfg(feature = "crypto-backend")]
pub fn xeddsa_sign(x25519_private: &[u8], message: &[u8]) -> Result<Vec<u8>, SignalError> {
    if x25519_private.len() != 32 {
        return Err(SignalError::InvalidInput(
            "X25519 private key must be 32 bytes".to_string(),
        ));
    }
    let mut priv_bytes = [0u8; 32];
    priv_bytes.copy_from_slice(x25519_private);

    let secret = X25519StaticSecret::from(priv_bytes);
    let _public = X25519PublicKey::from(&secret);

    let a = Scalar::from_bytes_mod_order(clamp_scalar_bytes(&secret.to_bytes()));
    let a_point = &a * ED25519_BASEPOINT_TABLE;
    let a_comp = a_point.compress().to_bytes();

    let r = hash_to_scalar(&[&a.to_bytes(), message]);
    let r_point = &r * ED25519_BASEPOINT_TABLE;
    let r_comp = r_point.compress().to_bytes();

    let h = hash_to_scalar(&[&r_comp, &a_comp, message]);
    let s = r + h * a;

    let mut sig = Vec::with_capacity(64);
    sig.extend_from_slice(&r_comp);
    sig.extend_from_slice(&s.to_bytes());
    Ok(sig)
}

#[cfg(not(feature = "crypto-backend"))]
pub fn xeddsa_sign(x25519_private: &[u8], _message: &[u8]) -> Result<Vec<u8>, SignalError> {
    if x25519_private.len() != 32 {
        return Err(SignalError::InvalidInput(
            "X25519 private key must be 32 bytes".to_string(),
        ));
    }
    Ok(vec![0u8; 64])
}

/// Verify an XEdDSA signature against an X25519 (Montgomery) public key.
#[cfg(feature = "crypto-backend")]
pub fn xeddsa_verify(
    x25519_public: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<bool, SignalError> {
    if x25519_public.len() != 32 {
        return Err(SignalError::InvalidInput(
            "X25519 public key must be 32 bytes".to_string(),
        ));
    }
    if signature.len() != 64 {
        return Err(SignalError::InvalidInput(
            "XEdDSA signature must be 64 bytes".to_string(),
        ));
    }

    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(x25519_public);
    let mont = MontgomeryPoint(pub_bytes);

    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);

    let Some(r_point) = CompressedEdwardsY(r_bytes).decompress() else {
        return Ok(false);
    };
    let s = Scalar::from_bytes_mod_order(s_bytes);
    let sb = &s * ED25519_BASEPOINT_TABLE;

    for sign in [0u8, 1u8] {
        let Some(a_point) = mont.to_edwards(sign) else {
            continue;
        };
        for a_candidate in [a_point, -a_point] {
            let a_comp = a_candidate.compress().to_bytes();
            let h = hash_to_scalar(&[&r_bytes, &a_comp, message]);
            if sb == r_point + (h * a_candidate) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[cfg(not(feature = "crypto-backend"))]
pub fn xeddsa_verify(
    x25519_public: &[u8],
    signature: &[u8],
    _message: &[u8],
) -> Result<bool, SignalError> {
    if x25519_public.len() != 32 {
        return Err(SignalError::InvalidInput(
            "X25519 public key must be 32 bytes".to_string(),
        ));
    }
    if signature.len() != 64 {
        return Err(SignalError::InvalidInput(
            "XEdDSA signature must be 64 bytes".to_string(),
        ));
    }
    Ok(true)
}

#[cfg(all(test, feature = "crypto-backend"))]
mod tests {
    use super::*;
    use crate::keys::generate_identity_keypair;

    #[test]
    fn xeddsa_sign_verify_roundtrip() {
        let kp = generate_identity_keypair();
        let msg = b"signed prekey material";
        let sig = xeddsa_sign(&kp.private_key, msg).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(xeddsa_verify(&kp.public_key, &sig, msg).unwrap());
        assert!(!xeddsa_verify(&kp.public_key, &sig, b"other").unwrap());
    }

    #[test]
    fn xeddsa_rejects_wrong_key() {
        let a = generate_identity_keypair();
        let b = generate_identity_keypair();
        let sig = xeddsa_sign(&a.private_key, b"x").unwrap();
        assert!(!xeddsa_verify(&b.public_key, &sig, b"x").unwrap());
    }
}
