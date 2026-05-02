//! Core cryptographic operations for Signal Protocol
//!
//! This module provides both:
//! - Real crypto implementations (enabled with `crypto-backend` feature)
//! - Abstract stubs for F* verification (when feature is disabled)

use crate::error::SignalError;

#[cfg(feature = "crypto-backend")]
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

#[cfg(feature = "crypto-backend")]
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Length in bytes of an X25519 public or private key, an Ed25519 private
/// key seed, an X25519 shared secret, and an HMAC-SHA-256 / chain key /
/// message key in the Signal Protocol.
pub const KEY_LEN: usize = 32;

/// Length in bytes of an Ed25519 detached signature.
pub const SIGNATURE_LEN: usize = 64;

#[cfg(feature = "crypto-backend")]
#[hax_lib::requires(true)]
#[hax_lib::ensures(|res| matches!(res, Ok(()) if public_key.len() == 32) || matches!(res, Err(_)))]
pub fn validate_x25519_public_key(public_key: &[u8]) -> Result<(), SignalError> {
    if public_key.len() != KEY_LEN {
        return Err(SignalError::InvalidInput(format!(
            "X25519 public key must be 32 bytes, got {}",
            public_key.len()
        )));
    }
    Ok(())
}

#[cfg(not(feature = "crypto-backend"))]
#[hax_lib::fstar::replace_body(
    r#"if Seq.length public_key <> 32 
    then Core_models.Result.Result_Err (Signal_protocol_core.Error.SignalError_InvalidInput (Alloc.String.String "X25519 public key must be 32 bytes"))
    else Core_models.Result.Result_Ok ()"#
)]
pub fn validate_x25519_public_key(public_key: &[u8]) -> Result<(), SignalError> {
    if public_key.len() != KEY_LEN {
        return Err(SignalError::InvalidInput(format!(
            "X25519 public key must be 32 bytes, got {}",
            public_key.len()
        )));
    }
    Ok(())
}

#[cfg(feature = "crypto-backend")]
#[hax_lib::requires(true)]
#[hax_lib::ensures(|res| matches!(res, Ok(s) if s.len() == 32) || matches!(res, Err(_)))]
pub fn x25519_ecdh(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, SignalError> {
    if private_key.len() != KEY_LEN {
        return Err(SignalError::InvalidInput(format!(
            "Private key must be 32 bytes, got {}",
            private_key.len()
        )));
    }

    validate_x25519_public_key(public_key)?;

    let mut private_bytes = [0u8; KEY_LEN];
    private_bytes.copy_from_slice(private_key);
    let secret = X25519StaticSecret::from(private_bytes);

    let mut public_bytes = [0u8; KEY_LEN];
    public_bytes.copy_from_slice(public_key);
    let public = X25519PublicKey::from(public_bytes);

    let shared_secret = secret.diffie_hellman(&public);
    Ok(shared_secret.as_bytes().to_vec())
}

#[cfg(not(feature = "crypto-backend"))]
#[hax_lib::fstar::replace_body(
    r#"if Seq.length private_key <> 32 
    then Core_models.Result.Result_Err (Signal_protocol_core.Error.SignalError_InvalidInput (Alloc.String.String "Private key must be 32 bytes"))
    else if Seq.length public_key <> 32
    then Core_models.Result.Result_Err (Signal_protocol_core.Error.SignalError_InvalidInput (Alloc.String.String "X25519 public key must be 32 bytes"))
    else Core_models.Result.Result_Ok (AbstractCrypto.bytes_to_vec (AbstractCrypto.dh private_key public_key))"#
)]
pub fn x25519_ecdh(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, SignalError> {
    if private_key.len() != KEY_LEN {
        return Err(SignalError::InvalidInput(
            "Private key must be 32 bytes".to_string(),
        ));
    }
    if public_key.len() != KEY_LEN {
        return Err(SignalError::InvalidInput(
            "X25519 public key must be 32 bytes".to_string(),
        ));
    }
    Ok(vec![0u8; KEY_LEN])
}

#[hax_lib::include]
pub fn simple_ecdh(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, SignalError> {
    x25519_ecdh(private_key, public_key)
}

/// HKDF-SHA-256 key derivation. Used for X3DH and the Double Ratchet
/// root-key derivation. The Double Ratchet symmetric chain-key /
/// message-key derivation uses [`hmac_sha256`] directly with the
/// constants `0x01` / `0x02` per the whitepaper §5.2.
#[hax_lib::include]
#[hax_lib::ensures(|res| matches!(res, Ok(o) if o.len() == output_len) || matches!(res, Err(_)))]
#[hax_lib::fstar::replace_body(
    r#"AbstractCrypto.hkdf_derive_vec e_salt e_input_key_material e_info output_len"#
)]
pub fn hkdf_derive(
    _salt: &[u8],
    _input_key_material: &[u8],
    _info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, SignalError> {
    #[cfg(feature = "crypto-backend")]
    {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(Some(_salt), _input_key_material);
        let mut output = vec![0u8; output_len];
        hkdf.expand(_info, &mut output)
            .map_err(|e| SignalError::KeyDerivation(format!("HKDF expand failed: {}", e)))?;
        Ok(output)
    }

    #[cfg(not(feature = "crypto-backend"))]
    {
        Ok(vec![0u8; output_len])
    }
}

/// HMAC-SHA-256 over `data` keyed by `key`. The Double Ratchet symmetric
/// KDF computes `message_key = HMAC(ck, 0x01)` and `next_ck = HMAC(ck,
/// 0x02)` per the Double Ratchet whitepaper §5.2.
#[hax_lib::include]
#[hax_lib::requires(key.len() == 32)]
#[hax_lib::ensures(|res| matches!(res, Ok(o) if o.len() == 32) || matches!(res, Err(_)))]
#[hax_lib::fstar::replace_body(
    r#"if Seq.length key <> 32
    then Core_models.Result.Result_Err (Signal_protocol_core.Error.SignalError_InvalidInput (Alloc.String.String "HMAC-SHA-256 key must be 32 bytes"))
    else Core_models.Result.Result_Ok (AbstractCrypto.bytes_to_vec (AbstractCrypto.hmac_sha256 key e_data))"#
)]
pub fn hmac_sha256(key: &[u8], _data: &[u8]) -> Result<Vec<u8>, SignalError> {
    if key.len() != KEY_LEN {
        return Err(SignalError::InvalidInput(
            "HMAC-SHA-256 key must be 32 bytes".to_string(),
        ));
    }

    #[cfg(feature = "crypto-backend")]
    {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
            .map_err(|e| SignalError::KeyDerivation(format!("HMAC init failed: {}", e)))?;
        mac.update(_data);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    #[cfg(not(feature = "crypto-backend"))]
    {
        Ok(vec![0u8; KEY_LEN])
    }
}

#[cfg(feature = "crypto-backend")]
#[hax_lib::requires(true)]
#[hax_lib::ensures(|res| matches!(res, Ok(s) if s.len() == 64) || matches!(res, Err(_)))]
pub fn sign_data_internal(private_key: &[u8], data: &[u8]) -> Result<Vec<u8>, SignalError> {
    if private_key.len() != KEY_LEN {
        return Err(SignalError::InvalidInput(
            "Ed25519 private key must be 32 bytes".to_string(),
        ));
    }

    let mut key_bytes = [0u8; KEY_LEN];
    key_bytes.copy_from_slice(private_key);
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let signature: Signature = signing_key.sign(data);
    Ok(signature.to_bytes().to_vec())
}

#[cfg(not(feature = "crypto-backend"))]
#[hax_lib::fstar::replace_body(
    r#"if Seq.length private_key <> 32 
    then Core_models.Result.Result_Err (Signal_protocol_core.Error.SignalError_InvalidInput (Alloc.String.String "Ed25519 private key must be 32 bytes"))
    else Core_models.Result.Result_Ok (AbstractCrypto.bytes_to_vec (AbstractCrypto.sign private_key e_data))"#
)]
pub fn sign_data_internal(private_key: &[u8], _data: &[u8]) -> Result<Vec<u8>, SignalError> {
    if private_key.len() != KEY_LEN {
        return Err(SignalError::InvalidInput(
            "Ed25519 private key must be 32 bytes".to_string(),
        ));
    }
    Ok(vec![0u8; SIGNATURE_LEN])
}

#[cfg(feature = "crypto-backend")]
#[hax_lib::requires(true)]
#[hax_lib::ensures(|res| matches!(res, Ok(_)) || matches!(res, Err(_)))]
pub fn verify_signature_internal(
    public_key: &[u8],
    signature: &[u8],
    data: &[u8],
) -> Result<bool, SignalError> {
    if public_key.len() != KEY_LEN {
        return Err(SignalError::InvalidInput(
            "Ed25519 public key must be 32 bytes".to_string(),
        ));
    }
    if signature.len() != SIGNATURE_LEN {
        return Err(SignalError::InvalidInput(
            "Ed25519 signature must be 64 bytes".to_string(),
        ));
    }

    let mut key_bytes = [0u8; KEY_LEN];
    key_bytes.copy_from_slice(public_key);
    let verifying_key = VerifyingKey::from_bytes(&key_bytes).map_err(|e| {
        SignalError::SignatureVerification(format!("Invalid Ed25519 public key: {}", e))
    })?;

    let mut sig_bytes = [0u8; SIGNATURE_LEN];
    sig_bytes.copy_from_slice(signature);
    let signature = Signature::from_bytes(&sig_bytes);
    let is_valid = verifying_key.verify(data, &signature).is_ok();
    Ok(is_valid)
}

#[cfg(not(feature = "crypto-backend"))]
#[hax_lib::fstar::replace_body(
    r#"if Seq.length public_key <> 32 
    then Core_models.Result.Result_Err (Signal_protocol_core.Error.SignalError_InvalidInput (Alloc.String.String "Ed25519 public key must be 32 bytes"))
    else if Seq.length signature <> 64
    then Core_models.Result.Result_Err (Signal_protocol_core.Error.SignalError_InvalidInput (Alloc.String.String "Ed25519 signature must be 64 bytes"))
    else Core_models.Result.Result_Ok (AbstractCrypto.verify public_key signature e_data)"#
)]
pub fn verify_signature_internal(
    public_key: &[u8],
    signature: &[u8],
    _data: &[u8],
) -> Result<bool, SignalError> {
    if public_key.len() != KEY_LEN {
        return Err(SignalError::InvalidInput(
            "Ed25519 public key must be 32 bytes".to_string(),
        ));
    }
    if signature.len() != SIGNATURE_LEN {
        return Err(SignalError::InvalidInput(
            "Ed25519 signature must be 64 bytes".to_string(),
        ));
    }
    Ok(true)
}

/// Constant-time equality of two byte slices. Returns `false` for slices
/// of different length (length itself is a non-secret).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}
