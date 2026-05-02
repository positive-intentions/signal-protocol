//! Double Ratchet implementation for the Signal Protocol.
//!
//! Mirrors the algorithm in the Signal Double Ratchet whitepaper version
//! 1.0 (<https://signal.org/docs/specifications/doubleratchet/>) and the
//! F* spec in `proofs/fstar/spec/Spec.DoubleRatchet.fst`.
//!
//! - Symmetric-key ratchet (whitepaper §5.2):
//!   ```text
//!     message_key  = HMAC-SHA256(chain_key, 0x01)
//!     next_chain_key = HMAC-SHA256(chain_key, 0x02)
//!   ```
//! - DH ratchet (§3.5): `(new_root_key, new_chain_key) = HKDF(salt = root_key,
//!   ikm = dh_out, info = "Signal_DH_Ratchet", 64)` split into two halves.

use crate::crypto::{ct_eq, hkdf_derive, hmac_sha256, simple_ecdh, KEY_LEN};
use crate::error::SignalError;
use crate::keys::generate_dh_ratchet_keypair;
use crate::types::KeyPair;
use std::collections::BTreeMap;
use std::fmt;
use zeroize::Zeroize;

/// Replace a secret-bearing `Option<Vec<u8>>` slot, zeroising the
/// previous value before dropping it. This is the binary-level
/// counterpart of the "old chain key wiped" assumption that
/// `formal-proofs/proverif/double_ratchet.pv` relies on for forward
/// secrecy: after `kdf_ck` advances the chain, the old chain key must
/// not be recoverable from process memory.
fn replace_secret_opt(slot: &mut Option<Vec<u8>>, new: Vec<u8>) {
    if let Some(mut old) = slot.replace(new) {
        old.zeroize();
    }
}

/// Replace a secret-bearing `Vec<u8>` field in place, zeroising the
/// previous value first.
fn replace_secret(slot: &mut Vec<u8>, new: Vec<u8>) {
    slot.zeroize();
    *slot = new;
}

/// Maximum number of message keys we are willing to derive in advance
/// when a peer's `message_number` exceeds our local counter. Bounds CPU
/// usage from a malicious peer that lies about its message number.
const MAX_SKIPPED_MESSAGE_KEYS: usize = 1000;

/// Single-byte HMAC inputs from Double Ratchet whitepaper §5.2.
const KDF_CK_MK_INPUT: &[u8] = &[0x01u8];
const KDF_CK_NEXT_CK_INPUT: &[u8] = &[0x02u8];

/// HKDF info string for the DH ratchet KDF (§3.5). Combined output is
/// 64 bytes split into a 32-byte root key and a 32-byte chain key.
const HKDF_INFO_DH_RATCHET: &[u8] = b"Signal_DH_Ratchet";

/// Composite key for the skipped-message-keys map: the DH public key
/// (which determines the chain) plus the message number on that chain.
/// Replaces the previous `String` ("hex:n") encoding.
pub type SkippedKey = (Vec<u8>, u32);

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
    pub skipped_message_keys: BTreeMap<SkippedKey, Vec<u8>>,
}

impl DoubleRatchetState {
    #[hax_lib::include]
    pub fn new() -> Self {
        DoubleRatchetState {
            root_key: vec![0u8; KEY_LEN],
            sending_chain_key: None,
            receiving_chain_key: None,
            sending_dh_keypair: None,
            receiving_dh_public_key: None,
            sending_message_number: 0,
            receiving_message_number: 0,
            previous_chain_length: 0,
            skipped_message_keys: BTreeMap::new(),
        }
    }
}

impl Default for DoubleRatchetState {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DoubleRatchetState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DoubleRatchetState")
            .field("sending_message_number", &self.sending_message_number)
            .field("receiving_message_number", &self.receiving_message_number)
            .field("previous_chain_length", &self.previous_chain_length)
            .field("skipped_message_keys_len", &self.skipped_message_keys.len())
            .field("has_sending_chain_key", &self.sending_chain_key.is_some())
            .field("has_receiving_chain_key", &self.receiving_chain_key.is_some())
            .field("has_sending_dh_keypair", &self.sending_dh_keypair.is_some())
            .field("has_receiving_dh_public_key", &self.receiving_dh_public_key.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct DoubleRatchetMessage {
    pub ciphertext: Vec<u8>,
    pub dh_public_key: Vec<u8>,
    pub message_number: u32,
    pub previous_chain_length: u32,
}

impl fmt::Debug for DoubleRatchetMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DoubleRatchetMessage")
            .field("ciphertext_len", &self.ciphertext.len())
            .field("dh_public_key_len", &self.dh_public_key.len())
            .field("message_number", &self.message_number)
            .field("previous_chain_length", &self.previous_chain_length)
            .finish_non_exhaustive()
    }
}

/// `KDF_CK` message-key half: `mk = HMAC-SHA256(ck, 0x01)`.
#[hax_lib::include]
#[hax_lib::requires(chain_key.len() == 32)]
#[hax_lib::ensures(|res| matches!(res, Ok(o) if o.len() == 32) || matches!(res, Err(_)))]
pub fn derive_message_key(chain_key: &[u8]) -> Result<Vec<u8>, SignalError> {
    hmac_sha256(chain_key, KDF_CK_MK_INPUT)
}

/// `KDF_CK` next-chain-key half: `next_ck = HMAC-SHA256(ck, 0x02)`.
#[hax_lib::include]
#[hax_lib::requires(chain_key.len() == 32)]
#[hax_lib::ensures(|res| matches!(res, Ok(o) if o.len() == 32) || matches!(res, Err(_)))]
pub fn derive_next_chain_key(chain_key: &[u8]) -> Result<Vec<u8>, SignalError> {
    hmac_sha256(chain_key, KDF_CK_NEXT_CK_INPUT)
}

#[hax_lib::include]
#[hax_lib::requires(new_remote_public_key.len() == 32)]
pub fn perform_dh_ratchet_step(
    state: &mut DoubleRatchetState,
    new_remote_public_key: &[u8],
) -> Result<(), SignalError> {
    let original_root_key = state.root_key.clone();

    let (new_root_key_for_receiving, receiving_chain_key) =
        if let Some(ref current_dh_keypair) = state.sending_dh_keypair {
            let dh_output = simple_ecdh(&current_dh_keypair.private_key, new_remote_public_key)?;

            let combined =
                hkdf_derive(&original_root_key, &dh_output, HKDF_INFO_DH_RATCHET, 64)?;

            let new_root_key = combined[0..32].to_vec();
            let recv_chain_key = combined[32..64].to_vec();
            (new_root_key, recv_chain_key)
        } else {
            // First DH ratchet from the responder side: no current sending
            // keypair yet, so the receiving chain is derived directly from
            // the X3DH-output root key. This matches Spec.DoubleRatchet
            // "initialize_responder + first_received_message".
            let recv_chain_key = hkdf_derive(
                b"Signal_Initial_Chain",
                &state.root_key,
                HKDF_INFO_DH_RATCHET,
                KEY_LEN,
            )?;
            (state.root_key.clone(), recv_chain_key)
        };

    replace_secret(&mut state.root_key, new_root_key_for_receiving);
    replace_secret_opt(&mut state.receiving_chain_key, receiving_chain_key);
    state.receiving_dh_public_key = Some(new_remote_public_key.to_vec());
    state.receiving_message_number = 0;

    let new_dh_keypair = generate_dh_ratchet_keypair();

    let root_key_for_sending = if state.sending_dh_keypair.is_some() {
        &state.root_key
    } else {
        &original_root_key
    };

    let sending_dh_output = simple_ecdh(&new_dh_keypair.private_key, new_remote_public_key)?;

    let combined = hkdf_derive(
        root_key_for_sending,
        &sending_dh_output,
        HKDF_INFO_DH_RATCHET,
        64,
    )?;

    replace_secret(&mut state.root_key, combined[0..32].to_vec());
    replace_secret_opt(&mut state.sending_chain_key, combined[32..64].to_vec());
    if let Some(mut old_kp) = state.sending_dh_keypair.replace(new_dh_keypair) {
        old_kp.private_key.zeroize();
    }
    state.previous_chain_length = state.sending_message_number;
    state.sending_message_number = 0;

    Ok(())
}

#[hax_lib::include]
pub fn skip_message_keys(
    state: &mut DoubleRatchetState,
    until_message_number: u32,
) -> Result<(), SignalError> {
    if state.receiving_message_number >= until_message_number {
        return Ok(());
    }

    let receiving_chain_key = match &state.receiving_chain_key {
        Some(key) => key.clone(),
        None => return Ok(()),
    };

    let skip_count = until_message_number - state.receiving_message_number;

    if skip_count > MAX_SKIPPED_MESSAGE_KEYS as u32 {
        return Err(SignalError::InvalidInput(format!(
            "Too many skipped message keys: {}",
            skip_count
        )));
    }

    // Every skipped key in this run is associated with the current
    // receiving DH public key; the BTreeMap stores `(dh_pk, n)` tuples
    // directly without the previous hex/string round-trip.
    let dh_public_key: Vec<u8> = state
        .receiving_dh_public_key
        .clone()
        .unwrap_or_default();

    let mut current_chain_key = receiving_chain_key;

    // hax cannot functionalize `while` loops (issues #15, #933). The bound
    // `skip_count <= MAX_SKIPPED_MESSAGE_KEYS` makes this loop terminating
    // by construction.
    for i in 0..skip_count {
        let message_key = derive_message_key(&current_chain_key)?;
        let message_number = state.receiving_message_number + i;
        state
            .skipped_message_keys
            .insert((dh_public_key.clone(), message_number), message_key);

        let next_chain_key = derive_next_chain_key(&current_chain_key)?;
        // The intermediate chain keys consumed inside this loop are
        // never re-derivable after the symmetric ratchet advances; wipe
        // them so a memory dump cannot recover the message keys we
        // just stored.
        current_chain_key.zeroize();
        current_chain_key = next_chain_key;
    }
    state.receiving_message_number = until_message_number;
    replace_secret_opt(&mut state.receiving_chain_key, current_chain_key);

    Ok(())
}

#[hax_lib::include]
#[hax_lib::requires(shared_secret.len() == 32)]
#[hax_lib::ensures(|res| matches!(res, Ok(s) if s.root_key.len() == 32) || matches!(res, Err(_)))]
pub fn initialize_double_ratchet_internal(
    shared_secret: &[u8],
    is_initiator: bool,
) -> Result<DoubleRatchetState, SignalError> {
    if shared_secret.len() != KEY_LEN {
        return Err(SignalError::InvalidInput(
            "Shared secret must be 32 bytes".to_string(),
        ));
    }

    let mut state = DoubleRatchetState::new();
    state.root_key = shared_secret.to_vec();

    if is_initiator {
        let keypair = generate_dh_ratchet_keypair();
        state.sending_dh_keypair = Some(keypair);

        let initial_chain_key = hkdf_derive(
            b"Signal_Initial_Chain",
            &state.root_key,
            HKDF_INFO_DH_RATCHET,
            KEY_LEN,
        )?;

        state.sending_chain_key = Some(initial_chain_key);
        state.sending_message_number = 0;
    } else {
        state.receiving_message_number = 0;
    }

    state.previous_chain_length = 0;
    Ok(state)
}

#[hax_lib::include]
pub fn double_ratchet_encrypt_internal(
    state: &mut DoubleRatchetState,
    plaintext: &[u8],
) -> Result<DoubleRatchetMessage, SignalError> {
    let sending_chain_key = state
        .sending_chain_key
        .as_ref()
        .ok_or_else(|| SignalError::InvalidInput("No sending chain key available".to_string()))?;

    let sending_dh_keypair = state
        .sending_dh_keypair
        .as_ref()
        .ok_or_else(|| SignalError::InvalidInput("No sending DH keypair available".to_string()))?;

    let message_key = derive_message_key(sending_chain_key)?;

    let (ciphertext, nonce) = aead_encrypt(&message_key, plaintext, &{
        let mut aad = Vec::new();
        aad.extend_from_slice(&sending_dh_keypair.public_key);
        aad.extend_from_slice(&state.sending_message_number.to_be_bytes());
        aad.extend_from_slice(&state.previous_chain_length.to_be_bytes());
        aad
    })?;

    let mut result_ciphertext = nonce;
    result_ciphertext.extend_from_slice(&ciphertext);

    let message = DoubleRatchetMessage {
        ciphertext: result_ciphertext,
        dh_public_key: sending_dh_keypair.public_key.clone(),
        message_number: state.sending_message_number,
        previous_chain_length: state.previous_chain_length,
    };

    let next_chain_key = derive_next_chain_key(sending_chain_key)?;
    replace_secret_opt(&mut state.sending_chain_key, next_chain_key);
    state.sending_message_number += 1;

    Ok(message)
}

#[hax_lib::include]
pub fn double_ratchet_decrypt_internal(
    state: &mut DoubleRatchetState,
    message: &DoubleRatchetMessage,
) -> Result<Vec<u8>, SignalError> {
    let message_dh_key = &message.dh_public_key;
    let message_number = message.message_number;
    let ciphertext_bytes = &message.ciphertext;

    // Constant-time DH-public-key comparison. Although the DH public key
    // is not itself secret, this avoids leaking timing information that
    // could be correlated with a peer's chain rotation pattern.
    let is_dh_ratchet_step = match state.receiving_dh_public_key.as_ref() {
        Some(current_dh_key) => !ct_eq(current_dh_key, message_dh_key),
        None => true,
    };

    if is_dh_ratchet_step {
        perform_dh_ratchet_step(state, message_dh_key)?;
    }

    let key_id: SkippedKey = (message_dh_key.clone(), message_number);

    let message_key = if let Some(skipped_key) = state.skipped_message_keys.remove(&key_id) {
        skipped_key
    } else {
        if message_number > state.receiving_message_number {
            skip_message_keys(state, message_number)?;
        }

        let receiving_chain_key = state.receiving_chain_key.as_ref().ok_or_else(|| {
            SignalError::InvalidInput("No receiving chain key available".to_string())
        })?;

        if message_number != state.receiving_message_number {
            return Err(SignalError::InvalidInput(format!(
                "Message number mismatch: expected {}, got {}",
                state.receiving_message_number, message_number
            )));
        }

        let message_key = derive_message_key(receiving_chain_key)?;

        let next_chain_key = derive_next_chain_key(receiving_chain_key)?;
        replace_secret_opt(&mut state.receiving_chain_key, next_chain_key);
        state.receiving_message_number += 1;

        message_key
    };

    if ciphertext_bytes.len() < 12 {
        return Err(SignalError::Decryption(
            "Ciphertext too short for nonce".to_string(),
        ));
    }

    let nonce_bytes = &ciphertext_bytes[..12];
    let encrypted_data = &ciphertext_bytes[12..];

    let aad = {
        let mut aad = Vec::new();
        aad.extend_from_slice(message_dh_key);
        aad.extend_from_slice(&message.message_number.to_be_bytes());
        aad.extend_from_slice(&message.previous_chain_length.to_be_bytes());
        aad
    };

    aead_decrypt(&message_key, encrypted_data, nonce_bytes, &aad)
}

#[hax_lib::include]
pub fn cleanup_skipped_message_keys_internal(
    state: &mut DoubleRatchetState,
    max_keys: usize,
) -> usize {
    let keys_to_remove = if state.skipped_message_keys.len() > max_keys {
        state.skipped_message_keys.len() - max_keys
    } else {
        return 0;
    };

    let mut keys: Vec<SkippedKey> = state.skipped_message_keys.keys().cloned().collect();
    keys.sort();

    let mut removed_count = 0;
    for key in keys.iter().take(keys_to_remove) {
        if let Some(mut mk) = state.skipped_message_keys.remove(key) {
            mk.zeroize();
        }
        removed_count += 1;
    }

    removed_count
}

#[hax_lib::include]
fn aead_encrypt(
    key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), SignalError> {
    #[cfg(feature = "crypto-backend")]
    {
        use aes_gcm::{
            aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
            Aes256Gcm,
        };
        use rand::RngCore;

        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

        let key_ga = GenericArray::from_slice(key);
        let cipher = Aes256Gcm::new(key_ga);
        let nonce_ga = GenericArray::from_slice(&nonce_bytes);

        let mut buffer = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(nonce_ga, aad, &mut buffer)
            .map_err(|e| SignalError::Encryption(format!("AES-GCM encryption failed: {}", e)))?;

        buffer.extend_from_slice(tag.as_slice());
        Ok((buffer, nonce_bytes.to_vec()))
    }

    #[cfg(not(feature = "crypto-backend"))]
    {
        let _ = (key, aad);
        let nonce = vec![0u8; 12];
        Ok((plaintext.to_vec(), nonce))
    }
}

#[hax_lib::include]
fn aead_decrypt(
    key: &[u8],
    ciphertext: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, SignalError> {
    #[cfg(feature = "crypto-backend")]
    {
        use aes_gcm::{
            aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
            Aes256Gcm,
        };
        type AesGcmTag = aes_gcm::aead::Tag<Aes256Gcm>;

        if ciphertext.len() < 16 {
            return Err(SignalError::Decryption(
                "Ciphertext too short for tag".to_string(),
            ));
        }

        let key_ga = GenericArray::from_slice(key);
        let cipher = Aes256Gcm::new(key_ga);
        let nonce_ga = GenericArray::from_slice(nonce);

        let encrypted_data = &ciphertext[..ciphertext.len() - 16];
        let tag_bytes = &ciphertext[ciphertext.len() - 16..];
        let tag = AesGcmTag::from_slice(tag_bytes);

        let mut buffer = encrypted_data.to_vec();
        cipher
            .decrypt_in_place_detached(nonce_ga, aad, &mut buffer, tag)
            .map_err(|e| SignalError::Decryption(format!("AES-GCM decryption failed: {}", e)))?;

        Ok(buffer)
    }

    #[cfg(not(feature = "crypto-backend"))]
    {
        let _ = (key, nonce, aad);
        Ok(ciphertext.to_vec())
    }
}
