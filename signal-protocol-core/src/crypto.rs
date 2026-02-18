//! Core cryptographic operations for Signal Protocol

use x25519_dalek::{StaticSecret as X25519StaticSecret, PublicKey as X25519PublicKey};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use crate::error::SignalError;

/// Validate that a public key is a valid X25519 point
pub fn validate_x25519_public_key(public_key: &[u8]) -> Result<(), SignalError> {
    if public_key.len() != 32 {
        return Err(SignalError::InvalidInput(format!(
            "X25519 public key must be 32 bytes, got {}",
            public_key.len()
        )));
    }
    Ok(())
}

/// Perform X25519 Elliptic Curve Diffie-Hellman key agreement
pub fn x25519_ecdh(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, SignalError> {
    if private_key.len() != 32 {
        return Err(SignalError::InvalidInput(format!(
            "Private key must be 32 bytes, got {}",
            private_key.len()
        )));
    }

    validate_x25519_public_key(public_key)?;

    let mut private_bytes = [0u8; 32];
    private_bytes.copy_from_slice(private_key);
    let secret = X25519StaticSecret::from(private_bytes);

    let mut public_bytes = [0u8; 32];
    public_bytes.copy_from_slice(public_key);
    let public = X25519PublicKey::from(public_bytes);

    let shared_secret = secret.diffie_hellman(&public);
    Ok(shared_secret.as_bytes().to_vec())
}

/// ECDH wrapper - returns Result for panic-free operation
pub fn simple_ecdh(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, SignalError> {
    x25519_ecdh(private_key, public_key)
}

/// Sign data using Ed25519
pub fn sign_data_internal(private_key: &[u8], data: &[u8]) -> Result<Vec<u8>, SignalError> {
    if private_key.len() != 32 {
        return Err(SignalError::InvalidInput("Ed25519 private key must be 32 bytes".to_string()));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(private_key);
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let signature: Signature = signing_key.sign(data);
    Ok(signature.to_bytes().to_vec())
}

/// Verify Ed25519 signature
pub fn verify_signature_internal(
    public_key: &[u8],
    signature: &[u8],
    data: &[u8],
) -> Result<bool, SignalError> {
    if public_key.len() != 32 {
        return Err(SignalError::InvalidInput("Ed25519 public key must be 32 bytes".to_string()));
    }
    if signature.len() != 64 {
        return Err(SignalError::InvalidInput("Ed25519 signature must be 64 bytes".to_string()));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(public_key);
    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| SignalError::SignatureVerification(format!("Invalid Ed25519 public key: {}", e)))?;

    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature);
    let signature = Signature::from_bytes(&sig_bytes);
    let is_valid = verifying_key.verify(data, &signature).is_ok();
    Ok(is_valid)
}
