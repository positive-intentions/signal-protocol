//! Message encryption and decryption for Signal Protocol (legacy helpers).
//!
//! SP-2026-011: message keys are not exported to JavaScript. Decrypt re-derives
//! the key from the shared secret and message number.

use crate::rust::crypto::uint8_array_to_vec;
use crate::rust::error::SignalError;
use crate::rust::types::EncryptionResult;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use js_sys::Uint8Array;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
use web_sys::console;

fn log(s: &str) {
    #[cfg(target_arch = "wasm32")]
    {
        console::log_1(&JsValue::from_str(s));
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        eprintln!("{}", s);
    }
}

fn derive_message_key(shared_secret: &[u8], message_number: u32) -> Result<[u8; 32], SignalError> {
    let salt = b"Signal_Message_Salt";
    let info = format!("Signal_Message_{}", message_number);
    let hkdf = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut message_key = [0u8; 32];
    hkdf.expand(info.as_bytes(), &mut message_key)
        .map_err(|e| SignalError::KeyDerivation(format!("HKDF expand failed: {}", e)))?;
    Ok(message_key)
}

pub(crate) fn encrypt_message_internal(
    shared_secret: &[u8],
    plaintext: &[u8],
    message_number: u32,
) -> Result<EncryptionResult, SignalError> {
    let message_key = derive_message_key(shared_secret, message_number)?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let key = GenericArray::from_slice(&message_key);
    let cipher = Aes256Gcm::new(key);
    let nonce_ga = GenericArray::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce_ga, plaintext)
        .expect("AES-GCM encrypt with valid key cannot fail");

    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);

    Ok(EncryptionResult {
        ciphertext: result,
    })
}

pub(crate) fn decrypt_message_internal(
    shared_secret: &[u8],
    ciphertext: &[u8],
    message_number: u32,
) -> Result<Vec<u8>, SignalError> {
    if ciphertext.len() < 12 {
        return Err(SignalError::Decryption(
            "Ciphertext too short (minimum 12 bytes for nonce)".to_string(),
        ));
    }

    let message_key = derive_message_key(shared_secret, message_number)?;
    let nonce_ga = GenericArray::from_slice(&ciphertext[..12]);
    let encrypted_data = &ciphertext[12..];

    let key = GenericArray::from_slice(&message_key);
    let cipher = Aes256Gcm::new(key);

    cipher
        .decrypt(nonce_ga, encrypted_data)
        .map_err(|e| SignalError::Decryption(format!("AES-GCM decryption failed: {}", e)))
}

#[wasm_bindgen]
pub fn encrypt_message(
    shared_secret: &Uint8Array,
    plaintext: &Uint8Array,
    message_number: u32,
) -> Result<EncryptionResult, JsValue> {
    log(&format!("Encrypting message #{}", message_number));

    let shared_secret_bytes = uint8_array_to_vec(shared_secret);
    let plaintext_bytes = uint8_array_to_vec(plaintext);

    match encrypt_message_internal(&shared_secret_bytes, &plaintext_bytes, message_number) {
        Ok(result) => {
            log("Message encryption completed successfully");
            Ok(result)
        }
        Err(e) => Err(JsValue::from_str(&e.to_string())),
    }
}

#[wasm_bindgen]
pub fn decrypt_message(
    shared_secret: &Uint8Array,
    ciphertext: &Uint8Array,
    message_number: u32,
) -> Result<Uint8Array, JsValue> {
    log(&format!("Decrypting message #{}", message_number));

    let shared_secret_bytes = uint8_array_to_vec(shared_secret);
    let ciphertext_bytes = uint8_array_to_vec(ciphertext);

    match decrypt_message_internal(&shared_secret_bytes, &ciphertext_bytes, message_number) {
        Ok(plaintext) => {
            log("Message decryption completed successfully");
            Ok(Uint8Array::from(&plaintext[..]))
        }
        Err(e) => Err(JsValue::from_str(&e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let shared = [9u8; 32];
        let pt = b"hello";
        let enc = encrypt_message_internal(&shared, pt, 1).unwrap();
        let dec = decrypt_message_internal(&shared, &enc.ciphertext, 1).unwrap();
        assert_eq!(dec, pt);
    }
}
