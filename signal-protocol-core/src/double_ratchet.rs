//! Double Ratchet Implementation for Signal Protocol

use sha2::Sha256;
use hkdf::Hkdf;
use aes_gcm::{Aes256Gcm, aead::{AeadInPlace, KeyInit}, Tag};
use aes_gcm::aead::generic_array::GenericArray;
use rand::RngCore;
use std::collections::HashMap;
use crate::crypto::simple_ecdh;
use crate::keys::generate_identity_keypair;
use crate::types::KeyPair;
use crate::error::SignalError;

const MAX_SKIPPED_MESSAGE_KEYS: usize = 1000;
const HKDF_INFO_CHAIN_KEY: &[u8] = b"Signal_DoubleRatchet_ChainKey";
const HKDF_INFO_MESSAGE_KEY: &[u8] = b"Signal_DoubleRatchet_MessageKey";

/// Double Ratchet state for one participant
#[derive(Clone)]
pub struct DoubleRatchetState {
    pub root_key: Vec<u8>,
    pub sending_chain_key: Option<Vec<u8>>,
    pub receiving_chain_key: Option<Vec<u8>>,
    pub sending_dh_keypair: Option<KeyPair>,
    pub receiving_dh_public_key: Option<Vec<u8>>,
    pub sending_message_number: u32,
    pub receiving_message_number: u32,
    pub previous_chain_length: u32,
    pub skipped_message_keys: HashMap<String, Vec<u8>>,
}

impl DoubleRatchetState {
    pub fn new() -> Self {
        DoubleRatchetState {
            root_key: vec![0u8; 32],
            sending_chain_key: None,
            receiving_chain_key: None,
            sending_dh_keypair: None,
            receiving_dh_public_key: None,
            sending_message_number: 0,
            receiving_message_number: 0,
            previous_chain_length: 0,
            skipped_message_keys: HashMap::new(),
        }
    }
}

/// Result of Double Ratchet message encryption
#[derive(Clone, Debug)]
pub struct DoubleRatchetMessage {
    pub ciphertext: Vec<u8>,
    pub dh_public_key: Vec<u8>,
    pub message_number: u32,
    pub previous_chain_length: u32,
}

/// Derive a message key from a chain key
#[cfg_attr(feature = "hax", hax_lib::include)]
pub fn derive_message_key(chain_key: &[u8]) -> Result<Vec<u8>, SignalError> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"Signal_Message_Salt"), chain_key);
    let mut message_key = [0u8; 32];
    hkdf.expand(HKDF_INFO_MESSAGE_KEY, &mut message_key)
        .map_err(|e| SignalError::KeyDerivation(format!("Message key derivation failed: {}", e)))?;
    Ok(message_key.to_vec())
}

/// Derive the next chain key from the current chain key
#[cfg_attr(feature = "hax", hax_lib::include)]
pub fn derive_next_chain_key(chain_key: &[u8]) -> Result<Vec<u8>, SignalError> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"Signal_Chain_Salt"), chain_key);
    let mut next_chain_key = [0u8; 32];
    hkdf.expand(HKDF_INFO_CHAIN_KEY, &mut next_chain_key)
        .map_err(|e| SignalError::KeyDerivation(format!("Next chain key derivation failed: {}", e)))?;
    Ok(next_chain_key.to_vec())
}

/// Perform a DH ratchet step
pub fn perform_dh_ratchet_step(
    state: &mut DoubleRatchetState,
    new_remote_public_key: &[u8],
) -> Result<(), SignalError> {
    let original_root_key = state.root_key.clone();

    let (new_root_key_for_receiving, receiving_chain_key) = if let Some(ref current_dh_keypair) = state.sending_dh_keypair {
        let dh_output = simple_ecdh(&current_dh_keypair.private_key, new_remote_public_key)?;

        let hkdf = Hkdf::<Sha256>::new(Some(b"Signal_DH_Ratchet"), &original_root_key);
        let mut hkdf_output = [0u8; 64];
        hkdf.expand(&dh_output, &mut hkdf_output)
            .map_err(|e| SignalError::KeyDerivation(format!("DH ratchet HKDF failed: {}", e)))?;

        let new_root_key = hkdf_output[0..32].to_vec();
        let receiving_chain_key = hkdf_output[32..64].to_vec();
        (new_root_key, receiving_chain_key)
    } else {
        let hkdf = Hkdf::<Sha256>::new(Some(b"Signal_Initial_Chain"), &state.root_key);
        let mut receiving_chain_key = [0u8; 32];
        hkdf.expand(HKDF_INFO_CHAIN_KEY, &mut receiving_chain_key)
            .map_err(|e| SignalError::KeyDerivation(format!("Initial receiving chain derivation failed: {}", e)))?;
        (state.root_key.clone(), receiving_chain_key.to_vec())
    };

    state.root_key = new_root_key_for_receiving;
    state.receiving_chain_key = Some(receiving_chain_key);
    state.receiving_dh_public_key = Some(new_remote_public_key.to_vec());
    state.receiving_message_number = 0;

    let new_dh_keypair = generate_identity_keypair();

    let root_key_for_sending = if state.sending_dh_keypair.is_some() {
        &state.root_key
    } else {
        &original_root_key
    };

    let sending_dh_output = simple_ecdh(&new_dh_keypair.private_key, new_remote_public_key)?;

    let hkdf = Hkdf::<Sha256>::new(Some(b"Signal_DH_Ratchet"), root_key_for_sending);
    let mut hkdf_output = [0u8; 64];
    hkdf.expand(&sending_dh_output, &mut hkdf_output)
        .map_err(|e| SignalError::KeyDerivation(format!("Sending chain HKDF failed: {}", e)))?;

    state.root_key = hkdf_output[0..32].to_vec();
    state.sending_chain_key = Some(hkdf_output[32..64].to_vec());
    state.sending_dh_keypair = Some(new_dh_keypair);
    state.previous_chain_length = state.sending_message_number;
    state.sending_message_number = 0;

    Ok(())
}

/// Skip message keys for out-of-order messages
pub fn skip_message_keys(
    state: &mut DoubleRatchetState,
    until_message_number: u32,
) -> Result<(), SignalError> {
    if let Some(ref mut receiving_chain_key) = state.receiving_chain_key {
        if state.receiving_message_number < until_message_number {
            let skip_count = until_message_number - state.receiving_message_number;

            if skip_count > MAX_SKIPPED_MESSAGE_KEYS as u32 {
                return Err(SignalError::InvalidInput(
                    format!("Too many skipped message keys: {}", skip_count)
                ));
            }

            let dh_public_key_hex = if let Some(ref dh_key) = state.receiving_dh_public_key {
                hex::encode(dh_key)
            } else {
                "none".to_string()
            };

            let mut current_chain_key = receiving_chain_key.clone();

            while state.receiving_message_number < until_message_number {
                let message_key = derive_message_key(&current_chain_key)?;
                let key_id = format!("{}:{}", dh_public_key_hex, state.receiving_message_number);
                state.skipped_message_keys.insert(key_id.clone(), message_key);

                current_chain_key = derive_next_chain_key(&current_chain_key)?;
                state.receiving_message_number += 1;
            }

            *receiving_chain_key = current_chain_key;
        }
    }

    Ok(())
}

/// Initialize Double Ratchet state from shared secret
pub fn initialize_double_ratchet_internal(
    shared_secret: &[u8],
    is_initiator: bool,
) -> Result<DoubleRatchetState, SignalError> {
    if shared_secret.len() != 32 {
        return Err(SignalError::InvalidInput("Shared secret must be 32 bytes".to_string()));
    }

    let mut state = DoubleRatchetState::new();
    state.root_key = shared_secret.to_vec();

    if is_initiator {
        let keypair = generate_identity_keypair();
        state.sending_dh_keypair = Some(keypair);

        let hkdf = Hkdf::<Sha256>::new(Some(b"Signal_Initial_Chain"), &state.root_key);
        let mut initial_chain_key = [0u8; 32];
        hkdf.expand(HKDF_INFO_CHAIN_KEY, &mut initial_chain_key)
            .map_err(|e| SignalError::KeyDerivation(format!("Initial chain key derivation failed: {}", e)))?;

        state.sending_chain_key = Some(initial_chain_key.to_vec());
        state.sending_message_number = 0;
    } else {
        state.receiving_message_number = 0;
    }

    state.previous_chain_length = 0;
    Ok(state)
}

/// Internal encrypt for native testing
pub fn double_ratchet_encrypt_internal(
    state: &mut DoubleRatchetState,
    plaintext: &[u8],
) -> Result<DoubleRatchetMessage, SignalError> {
    let sending_chain_key = state.sending_chain_key.as_ref()
        .ok_or_else(|| SignalError::InvalidInput("No sending chain key available".to_string()))?;

    let sending_dh_keypair = state.sending_dh_keypair.as_ref()
        .ok_or_else(|| SignalError::InvalidInput("No sending DH keypair available".to_string()))?;

    let message_key = derive_message_key(sending_chain_key)?;

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let mut aad = Vec::new();
    aad.extend_from_slice(&sending_dh_keypair.public_key);
    aad.extend_from_slice(&state.sending_message_number.to_be_bytes());
    aad.extend_from_slice(&state.previous_chain_length.to_be_bytes());

    let key = GenericArray::from_slice(&message_key);
    let cipher = Aes256Gcm::new(key);
    let nonce_ga = GenericArray::from_slice(&nonce_bytes);

    let mut buffer = plaintext.to_vec();
    let tag = cipher.encrypt_in_place_detached(nonce_ga, aad.as_slice(), &mut buffer)
        .map_err(|e| SignalError::Encryption(format!("AES-GCM encryption failed: {}", e)))?;

    let mut result_ciphertext = nonce_bytes.to_vec();
    result_ciphertext.extend_from_slice(&buffer);
    result_ciphertext.extend_from_slice(tag.as_slice());

    let message = DoubleRatchetMessage {
        ciphertext: result_ciphertext,
        dh_public_key: sending_dh_keypair.public_key.clone(),
        message_number: state.sending_message_number,
        previous_chain_length: state.previous_chain_length,
    };

    let next_chain_key = derive_next_chain_key(sending_chain_key)?;
    state.sending_chain_key = Some(next_chain_key);
    state.sending_message_number += 1;

    Ok(message)
}

/// Internal decrypt for native testing
pub fn double_ratchet_decrypt_internal(
    state: &mut DoubleRatchetState,
    message: &DoubleRatchetMessage,
) -> Result<Vec<u8>, SignalError> {
    let message_dh_key = &message.dh_public_key;
    let message_number = message.message_number;
    let ciphertext_bytes = &message.ciphertext;

    let is_dh_ratchet_step = if let Some(ref current_dh_key) = state.receiving_dh_public_key {
        current_dh_key != message_dh_key
    } else {
        true
    };

    if is_dh_ratchet_step {
        perform_dh_ratchet_step(state, message_dh_key)?;
    }

    let dh_key_hex = hex::encode(message_dh_key);
    let key_id = format!("{}:{}", dh_key_hex, message_number);

    let message_key = if let Some(skipped_key) = state.skipped_message_keys.remove(&key_id) {
        skipped_key
    } else {
        if message_number > state.receiving_message_number {
            skip_message_keys(state, message_number)?;
        }

        let receiving_chain_key = state.receiving_chain_key.as_ref()
            .ok_or_else(|| SignalError::InvalidInput("No receiving chain key available".to_string()))?;

        if message_number != state.receiving_message_number {
            return Err(SignalError::InvalidInput(format!(
                "Message number mismatch: expected {}, got {}",
                state.receiving_message_number, message_number
            )));
        }

        let message_key = derive_message_key(receiving_chain_key)?;

        let next_chain_key = derive_next_chain_key(receiving_chain_key)?;
        state.receiving_chain_key = Some(next_chain_key);
        state.receiving_message_number += 1;

        message_key
    };

    if ciphertext_bytes.len() < 12 + 16 {
        return Err(SignalError::Decryption("Ciphertext too short for nonce and tag".to_string()));
    }

    let nonce_bytes = &ciphertext_bytes[..12];
    let encrypted_data = &ciphertext_bytes[12..ciphertext_bytes.len() - 16];
    let tag_bytes = &ciphertext_bytes[ciphertext_bytes.len() - 16..];

    let mut aad = Vec::new();
    aad.extend_from_slice(message_dh_key);
    aad.extend_from_slice(&message.message_number.to_be_bytes());
    aad.extend_from_slice(&message.previous_chain_length.to_be_bytes());

    let key = GenericArray::from_slice(&message_key);
    let cipher = Aes256Gcm::new(key);
    let nonce_ga = GenericArray::from_slice(nonce_bytes);
    let tag = Tag::from_slice(tag_bytes);

    let mut buffer = encrypted_data.to_vec();
    cipher.decrypt_in_place_detached(nonce_ga, aad.as_slice(), &mut buffer, tag)
        .map_err(|e| SignalError::Decryption(format!("AES-GCM decryption failed: {}", e)))?;

    Ok(buffer)
}

/// Cleanup old skipped message keys
pub fn cleanup_skipped_message_keys_internal(
    state: &mut DoubleRatchetState,
    max_keys: usize,
) -> usize {
    let keys_to_remove = if state.skipped_message_keys.len() > max_keys {
        state.skipped_message_keys.len() - max_keys
    } else {
        return 0;
    };

    let mut keys: Vec<_> = state.skipped_message_keys.keys().cloned().collect();
    keys.sort();

    let mut removed_count = 0;
    for key in keys.iter().take(keys_to_remove) {
        state.skipped_message_keys.remove(key);
        removed_count += 1;
    }

    removed_count
}
