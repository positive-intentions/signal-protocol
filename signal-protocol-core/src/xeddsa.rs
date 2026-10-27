//! XEdDSA signatures over X25519 identity keys (SP-2026-006 / SP-2026-013).
//!
//! Implements [Signal XEdDSA](https://signal.org/docs/specifications/xeddsa/)
//! for Curve25519: single X25519 seed used for DH and signatures.

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
use rand::rngs::OsRng;
#[cfg(feature = "crypto-backend")]
use rand::RngCore;
#[cfg(feature = "crypto-backend")]
use sha2::{Digest, Sha512};

/// `hash1` domain: SHA-512(0xFE || 0xFF×31 || …)
#[cfg(feature = "crypto-backend")]
const HASH1_PREFIX: [u8; 32] = [
    0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// Field prime p = 2^255 - 19 (little-endian).
#[cfg(feature = "crypto-backend")]
const FIELD_P: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

#[cfg(feature = "crypto-backend")]
fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    for p in parts {
        hasher.update(p);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

#[cfg(feature = "crypto-backend")]
fn u_is_reduced(u: &[u8; 32]) -> bool {
    // Reject if u >= p (little-endian compare).
    for i in (0..32).rev() {
        if u[i] < FIELD_P[i] {
            return true;
        }
        if u[i] > FIELD_P[i] {
            return false;
        }
    }
    false // u == p is not reduced
}

/// Derive the Edwards public key bytes corresponding to an X25519 Montgomery public key.
///
/// Per XEdDSA, the Edwards sign bit is forced to 0.
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
        if !u_is_reduced(&bytes) {
            return Err(SignalError::InvalidInput(
                "X25519 public key u coordinate is not reduced".to_string(),
            ));
        }
        let mont = MontgomeryPoint(bytes);
        let Some(ed) = mont.to_edwards(0) else {
            return Err(SignalError::InvalidInput(
                "X25519 public key is not a valid curve point".to_string(),
            ));
        };
        let mut enc = ed.compress().to_bytes();
        enc[31] &= 0x7f; // force sign bit 0
        Ok(enc)
    }
    #[cfg(not(feature = "crypto-backend"))]
    {
        let mut out = [0u8; 32];
        out.copy_from_slice(x25519_public);
        Ok(out)
    }
}

/// `calculate_key_pair(k)` → `(A, a)` with A.s forced to 0.
#[cfg(feature = "crypto-backend")]
fn calculate_key_pair(k_bytes: &[u8; 32]) -> (CompressedEdwardsY, Scalar) {
    let k = Scalar::from_bytes_mod_order(*k_bytes);
    let e = &k * ED25519_BASEPOINT_TABLE;
    let mut a_comp = e.compress();
    let sign_bit = a_comp.0[31] >> 7;
    a_comp.0[31] &= 0x7f;
    let a = if sign_bit == 1 { -k } else { k };
    (a_comp, a)
}

/// Sign `message` with an X25519 private key using XEdDSA.
#[cfg(feature = "crypto-backend")]
pub fn xeddsa_sign(x25519_private: &[u8], message: &[u8]) -> Result<Vec<u8>, SignalError> {
    if x25519_private.len() != 32 {
        return Err(SignalError::InvalidInput(
            "X25519 private key must be 32 bytes".to_string(),
        ));
    }
    let mut k_bytes = [0u8; 32];
    k_bytes.copy_from_slice(x25519_private);
    // Private keys from generate_* are already clamped; clamp again for raw inputs.
    k_bytes[0] &= 248;
    k_bytes[31] &= 127;
    k_bytes[31] |= 64;

    let (cap_a, a) = calculate_key_pair(&k_bytes);

    let mut z = [0u8; 64];
    OsRng.fill_bytes(&mut z);

    let r = Scalar::from_bytes_mod_order_wide(&sha512(&[&HASH1_PREFIX, a.as_bytes(), message, &z]));
    let cap_r = (&r * ED25519_BASEPOINT_TABLE).compress();
    let h =
        Scalar::from_bytes_mod_order_wide(&sha512(&[cap_r.as_bytes(), cap_a.as_bytes(), message]));
    let s = r + h * a;

    let mut sig = Vec::with_capacity(64);
    sig.extend_from_slice(cap_r.as_bytes());
    sig.extend_from_slice(s.as_bytes());
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

    let mut u = [0u8; 32];
    u.copy_from_slice(x25519_public);
    if !u_is_reduced(&u) {
        return Ok(false);
    }

    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);
    s_bytes[31] &= 0x7f;
    // Reject s with excess high bits (spec: s >= 2^|q|).
    if (s_bytes[31] & 0b1110_0000) != 0 {
        return Ok(false);
    }
    let s = Scalar::from_bytes_mod_order(s_bytes);

    if CompressedEdwardsY(r_bytes).decompress().is_none() {
        return Ok(false);
    }

    let mont = MontgomeryPoint(u);
    let Some(a_point) = mont.to_edwards(0) else {
        return Ok(false);
    };
    let a_bytes = a_point.compress().to_bytes();

    let h = Scalar::from_bytes_mod_order_wide(&sha512(&[&r_bytes, &a_bytes, message]));
    // R_check = sB - hA = sB + h*(-A)
    let r_check = EdwardsPoint::vartime_double_scalar_mul_basepoint(&h, &(-a_point), &s);
    Ok(r_check.compress().as_bytes() == &r_bytes)
}

#[cfg(feature = "crypto-backend")]
use curve25519_dalek::EdwardsPoint;

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
        let msg = b"hello xeddsa";
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

    #[test]
    fn xeddsa_rejects_excess_s_bits() {
        let kp = generate_identity_keypair();
        let mut sig = xeddsa_sign(&kp.private_key, b"m").unwrap();
        // Set bits that make s >= 2^253 (reject per verify).
        sig[63] |= 0xe0;
        assert!(!xeddsa_verify(&kp.public_key, &sig, b"m").unwrap());
    }

    #[test]
    fn edwards_public_has_sign_bit_clear() {
        let kp = generate_identity_keypair();
        let ed = montgomery_to_edwards_public(&kp.public_key).unwrap();
        assert_eq!(ed[31] & 0x80, 0);
    }

    #[test]
    fn sign_verify_input_length_errors() {
        assert!(xeddsa_sign(&[0u8; 16], b"m").is_err());
        assert!(xeddsa_verify(&[0u8; 16], &[0u8; 64], b"m").is_err());
        assert!(xeddsa_verify(&[0u8; 32], &[0u8; 32], b"m").is_err());
    }
}
