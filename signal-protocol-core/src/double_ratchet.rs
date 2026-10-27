//! Double Ratchet Implementation for Signal Protocol
//!
//! SP-2026 remediations: commit-after-AEAD, PN previous-chain skip, skipped-key
//! bounds with FIFO eviction, counter overflow checks, IK-bound associated data.

use crate::crypto::{hkdf_derive, simple_ecdh};
use crate::error::SignalError;
use crate::keys::generate_identity_keypair;
use crate::types::KeyPair;
use std::collections::BTreeMap;

const MAX_SKIP_PER_CHAIN: usize = 1000;
const MAX_SKIPPED_TOTAL: usize = 1000;
const HKDF_INFO_CHAIN_KEY: &[u8] = b"Signal_DoubleRatchet_ChainKey";
const HKDF_INFO_MESSAGE_KEY: &[u8] = b"Signal_DoubleRatchet_MessageKey";

/// HKDF with a short fixed output length (≤ 64) cannot fail for SHA-256 expand.
#[cfg_attr(coverage_nightly, coverage(off))]
fn hkdf_derive_short(
    salt: &[u8],
    input_key_material: &[u8],
    info: &[u8],
    output_len: usize,
) -> Vec<u8> {
    hkdf_derive(salt, input_key_material, info, output_len)
        .expect("HKDF expand with short output cannot fail")
}

fn skipped_key_id(dh_public: &[u8], message_number: u32) -> String {
    format!("{}:{}", hex::encode(dh_public), message_number)
}

#[derive(Clone, Debug)]
#[cfg_attr(not(hax_compilation), derive(serde::Serialize, serde::Deserialize))]
pub struct DoubleRatchetState {
    pub root_key: Vec<u8>,
    pub sending_chain_key: Option<Vec<u8>>,
    pub receiving_chain_key: Option<Vec<u8>>,
    pub sending_dh_keypair: Option<KeyPair>,
    pub receiving_dh_public_key: Option<Vec<u8>>,
    pub sending_message_number: u32,
    pub receiving_message_number: u32,
    pub previous_chain_length: u32,
    pub skipped_message_keys: BTreeMap<String, Vec<u8>>,
    /// Insertion order for FIFO eviction (SP-2026-008).
    pub skipped_key_order: Vec<String>,
    /// Session associated data bound into every AEAD (SP-2026-005).
    pub associated_data: Vec<u8>,
}

impl DoubleRatchetState {
    #[hax_lib::include]
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
            skipped_message_keys: BTreeMap::new(),
            skipped_key_order: Vec::new(),
            associated_data: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(not(hax_compilation), derive(serde::Serialize, serde::Deserialize))]
pub struct DoubleRatchetMessage {
    pub ciphertext: Vec<u8>,
    pub dh_public_key: Vec<u8>,
    pub message_number: u32,
    pub previous_chain_length: u32,
}

fn build_message_aad(session_ad: &[u8], dh: &[u8], n: u32, pn: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(session_ad.len() + dh.len() + 8);
    aad.extend_from_slice(session_ad);
    aad.extend_from_slice(dh);
    aad.extend_from_slice(&n.to_be_bytes());
    aad.extend_from_slice(&pn.to_be_bytes());
    aad
}

fn insert_skipped_key(
    state: &mut DoubleRatchetState,
    key_id: String,
    message_key: Vec<u8>,
) -> Result<(), SignalError> {
    if !state.skipped_message_keys.contains_key(&key_id) {
        // SP-2026-008: FIFO-evict oldest when at capacity (do not hard-fail decrypt).
        while state.skipped_message_keys.len() >= MAX_SKIPPED_TOTAL {
            if let Some(oldest) = state.skipped_key_order.first().cloned() {
                remove_skipped_key(state, &oldest);
            } else {
                break;
            }
        }
        state.skipped_key_order.push(key_id.clone());
    }
    state.skipped_message_keys.insert(key_id, message_key);
    Ok(())
}

fn remove_skipped_key(state: &mut DoubleRatchetState, key_id: &str) -> Option<Vec<u8>> {
    let key = state.skipped_message_keys.remove(key_id)?;
    if let Some(pos) = state.skipped_key_order.iter().position(|k| k == key_id) {
        state.skipped_key_order.remove(pos);
    }
    Some(key)
}

#[hax_lib::include]
pub fn derive_message_key(chain_key: &[u8]) -> Result<Vec<u8>, SignalError> {
    Ok(hkdf_derive_short(
        b"Signal_Message_Salt",
        chain_key,
        HKDF_INFO_MESSAGE_KEY,
        32,
    ))
}

#[hax_lib::include]
pub fn derive_next_chain_key(chain_key: &[u8]) -> Result<Vec<u8>, SignalError> {
    Ok(hkdf_derive_short(
        b"Signal_Chain_Salt",
        chain_key,
        HKDF_INFO_CHAIN_KEY,
        32,
    ))
}

#[hax_lib::include]
pub fn perform_dh_ratchet_step(
    state: &mut DoubleRatchetState,
    new_remote_public_key: &[u8],
) -> Result<(), SignalError> {
    let original_root_key = state.root_key.clone();

    let current_dh_keypair = state.sending_dh_keypair.as_ref().ok_or_else(|| {
        SignalError::InvalidInput(
            "DH ratchet requires a local ratchet keypair (responder must seed SPK)".to_string(),
        )
    })?;
    let dh_output = simple_ecdh(&current_dh_keypair.private_key, new_remote_public_key)?;
    let combined = hkdf_derive_short(b"Signal_DH_Ratchet", &original_root_key, &dh_output, 64);
    state.root_key = combined[0..32].to_vec();
    state.receiving_chain_key = Some(combined[32..64].to_vec());
    state.receiving_dh_public_key = Some(new_remote_public_key.to_vec());
    state.receiving_message_number = 0;

    let new_dh_keypair = generate_identity_keypair();
    let sending_dh_output = simple_ecdh(&new_dh_keypair.private_key, new_remote_public_key)?;
    let combined = hkdf_derive_short(
        b"Signal_DH_Ratchet",
        &state.root_key,
        &sending_dh_output,
        64,
    );

    state.root_key = combined[0..32].to_vec();
    state.sending_chain_key = Some(combined[32..64].to_vec());
    state.sending_dh_keypair = Some(new_dh_keypair);
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

    if skip_count as usize > MAX_SKIP_PER_CHAIN {
        return Err(SignalError::InvalidInput(format!(
            "Too many skipped message keys in one chain: {}",
            skip_count
        )));
    }

    let dh_public = match &state.receiving_dh_public_key {
        Some(dh_key) => dh_key.clone(),
        None => return Ok(()),
    };

    let mut current_chain_key = receiving_chain_key;

    for i in 0..skip_count {
        let message_key = derive_message_key(&current_chain_key)?;
        let message_number = state.receiving_message_number + i;
        let key_id = skipped_key_id(&dh_public, message_number);
        insert_skipped_key(state, key_id, message_key)?;
        current_chain_key = derive_next_chain_key(&current_chain_key)?;
    }
    state.receiving_message_number = until_message_number;
    state.receiving_chain_key = Some(current_chain_key);

    Ok(())
}

/// Role-specific Double Ratchet initialization (SP-2026-012).
///
/// Fail-closed: initiator must supply Bob's SPK public; responder must supply
/// the matching local SPK keypair. Associated data must be non-empty
/// (typically `IK_A || IK_B` from X3DH).
pub enum RatchetRole<'a> {
    /// Alice: first sending chain includes DH against Bob's SPK.
    Initiator { remote_spk_public: &'a [u8] },
    /// Bob: seed sending DH with the published SPK so Alice's first message matches.
    Responder { local_spk: &'a KeyPair },
}

/// Initialize a Double Ratchet session (only secure init path).
#[hax_lib::include]
pub fn initialize_double_ratchet(
    shared_secret: &[u8],
    associated_data: &[u8],
    role: RatchetRole<'_>,
) -> Result<DoubleRatchetState, SignalError> {
    if shared_secret.len() != 32 {
        return Err(SignalError::InvalidInput(
            "Shared secret must be 32 bytes".to_string(),
        ));
    }
    if associated_data.is_empty() {
        return Err(SignalError::InvalidInput(
            "Associated data must be non-empty (IK_A || IK_B)".to_string(),
        ));
    }

    let mut state = DoubleRatchetState::new();
    state.root_key = shared_secret.to_vec();
    state.associated_data = associated_data.to_vec();
    state.previous_chain_length = 0;

    match role {
        RatchetRole::Initiator { remote_spk_public } => {
            if remote_spk_public.len() != 32 {
                return Err(SignalError::InvalidInput(
                    "Remote SPK public must be 32 bytes".to_string(),
                ));
            }
            let keypair = generate_identity_keypair();
            let dh_output = simple_ecdh(&keypair.private_key, remote_spk_public)?;
            let combined = hkdf_derive_short(b"Signal_DH_Ratchet", &state.root_key, &dh_output, 64);
            state.root_key = combined[0..32].to_vec();
            state.sending_chain_key = Some(combined[32..64].to_vec());
            state.receiving_dh_public_key = Some(remote_spk_public.to_vec());
            state.sending_dh_keypair = Some(keypair);
            state.sending_message_number = 0;
        }
        RatchetRole::Responder { local_spk } => {
            if local_spk.public_key.len() != 32 || local_spk.private_key.len() != 32 {
                return Err(SignalError::InvalidInput(
                    "Local SPK keypair must be 32-byte keys".to_string(),
                ));
            }
            state.sending_dh_keypair = Some(local_spk.clone());
            state.receiving_message_number = 0;
        }
    }

    Ok(state)
}

/// Build a matching Alice/Bob session pair for tests (shared SPK).
pub fn test_ratchet_pair(
    shared_secret: &[u8],
    associated_data: &[u8],
) -> Result<(DoubleRatchetState, DoubleRatchetState, KeyPair), SignalError> {
    let bob_spk = generate_identity_keypair();
    let alice = initialize_double_ratchet(
        shared_secret,
        associated_data,
        RatchetRole::Initiator {
            remote_spk_public: &bob_spk.public_key,
        },
    )?;
    let bob = initialize_double_ratchet(
        shared_secret,
        associated_data,
        RatchetRole::Responder {
            local_spk: &bob_spk,
        },
    )?;
    Ok((alice, bob, bob_spk))
}

#[hax_lib::include]
pub fn double_ratchet_encrypt_internal(
    state: &mut DoubleRatchetState,
    plaintext: &[u8],
) -> Result<DoubleRatchetMessage, SignalError> {
    if state.sending_message_number == u32::MAX {
        return Err(SignalError::InvalidInput(
            "Sending message number overflow".to_string(),
        ));
    }

    let sending_chain_key = state
        .sending_chain_key
        .as_ref()
        .ok_or_else(|| SignalError::InvalidInput("No sending chain key available".to_string()))?
        .clone();

    let sending_dh_public = state
        .sending_dh_keypair
        .as_ref()
        .ok_or_else(|| SignalError::InvalidInput("No sending DH keypair available".to_string()))?
        .public_key
        .clone();

    let message_key = derive_message_key(&sending_chain_key)?;
    let aad = build_message_aad(
        &state.associated_data,
        &sending_dh_public,
        state.sending_message_number,
        state.previous_chain_length,
    );

    let (ciphertext, nonce) = aead_encrypt(&message_key, plaintext, &aad)?;

    let mut result_ciphertext = nonce;
    result_ciphertext.extend_from_slice(&ciphertext);

    let message = DoubleRatchetMessage {
        ciphertext: result_ciphertext,
        dh_public_key: sending_dh_public,
        message_number: state.sending_message_number,
        previous_chain_length: state.previous_chain_length,
    };

    let next_chain_key = derive_next_chain_key(&sending_chain_key)?;
    state.sending_chain_key = Some(next_chain_key);
    state.sending_message_number += 1;

    Ok(message)
}

fn try_skipped_message_key(
    state: &mut DoubleRatchetState,
    message: &DoubleRatchetMessage,
) -> Result<Option<Vec<u8>>, SignalError> {
    let key_id = skipped_key_id(&message.dh_public_key, message.message_number);
    let Some(message_key) = state.skipped_message_keys.get(&key_id).cloned() else {
        return Ok(None);
    };

    let plaintext = decrypt_with_key(state, message, &message_key)?;
    // Only remove after successful AEAD (SP-2026-003).
    remove_skipped_key(state, &key_id);
    Ok(Some(plaintext))
}

fn decrypt_with_key(
    state: &DoubleRatchetState,
    message: &DoubleRatchetMessage,
    message_key: &[u8],
) -> Result<Vec<u8>, SignalError> {
    let ciphertext_bytes = &message.ciphertext;
    if ciphertext_bytes.len() < 12 {
        return Err(SignalError::Decryption(
            "Ciphertext too short for nonce".to_string(),
        ));
    }
    let nonce_bytes = &ciphertext_bytes[..12];
    let encrypted_data = &ciphertext_bytes[12..];
    let aad = build_message_aad(
        &state.associated_data,
        &message.dh_public_key,
        message.message_number,
        message.previous_chain_length,
    );
    aead_decrypt(message_key, encrypted_data, nonce_bytes, &aad)
}

fn decrypt_on_state(
    state: &mut DoubleRatchetState,
    message: &DoubleRatchetMessage,
) -> Result<Vec<u8>, SignalError> {
    if let Some(plaintext) = try_skipped_message_key(state, message)? {
        return Ok(plaintext);
    }

    let message_dh_key = &message.dh_public_key;
    let message_number = message.message_number;

    let is_dh_ratchet_step = match &state.receiving_dh_public_key {
        Some(current) => current != message_dh_key,
        None => true,
    };

    if is_dh_ratchet_step {
        // Archive remaining keys on the *current* receiving chain using PN (SP-2026-001).
        if state.receiving_chain_key.is_some() && state.receiving_dh_public_key.is_some() {
            skip_message_keys(state, message.previous_chain_length)?;
        }
        perform_dh_ratchet_step(state, message_dh_key)?;
        skip_message_keys(state, message_number)?;
    } else if message_number > state.receiving_message_number {
        skip_message_keys(state, message_number)?;
    }

    let receiving_chain_key = state
        .receiving_chain_key
        .as_ref()
        .ok_or_else(|| SignalError::InvalidInput("No receiving chain key available".to_string()))?;

    if message_number != state.receiving_message_number {
        return Err(SignalError::InvalidInput(format!(
            "Message number mismatch: expected {}, got {}",
            state.receiving_message_number, message_number
        )));
    }

    if state.receiving_message_number == u32::MAX {
        return Err(SignalError::InvalidInput(
            "Receiving message number overflow".to_string(),
        ));
    }

    let message_key = derive_message_key(receiving_chain_key)?;
    let next_chain_key = derive_next_chain_key(receiving_chain_key)?;

    let plaintext = decrypt_with_key(state, message, &message_key)?;

    state.receiving_chain_key = Some(next_chain_key);
    state.receiving_message_number += 1;

    Ok(plaintext)
}

/// Decrypt and commit state only after AEAD succeeds (SP-2026-002).
#[hax_lib::include]
pub fn double_ratchet_decrypt_internal(
    state: &mut DoubleRatchetState,
    message: &DoubleRatchetMessage,
) -> Result<Vec<u8>, SignalError> {
    let mut tentative = state.clone();
    let plaintext = decrypt_on_state(&mut tentative, message)?;
    *state = tentative;
    Ok(plaintext)
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

    let mut removed_count = 0;
    while removed_count < keys_to_remove && !state.skipped_key_order.is_empty() {
        let key_id = state.skipped_key_order.remove(0);
        state.skipped_message_keys.remove(&key_id);
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
            .expect("AES-GCM encrypt with valid key cannot fail");

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

#[cfg(all(test, feature = "crypto-backend"))]
mod tests {
    use super::*;
    use crate::keys::generate_identity_keypair;

    fn shared_secret() -> [u8; 32] {
        [0x42u8; 32]
    }

    fn ad() -> &'static [u8] {
        b"IK_A||IK_B_test_ad______________"
    }

    fn pair() -> (DoubleRatchetState, DoubleRatchetState) {
        let (alice, bob, _) = test_ratchet_pair(&shared_secret(), ad()).unwrap();
        (alice, bob)
    }

    #[test]
    fn state_new_defaults() {
        let s = DoubleRatchetState::new();
        assert_eq!(s.root_key.len(), 32);
        assert!(s.sending_chain_key.is_none());
        assert!(s.receiving_chain_key.is_none());
        assert!(s.skipped_message_keys.is_empty());
        assert!(s.skipped_key_order.is_empty());
        let _ = format!("{:?}", s);
    }

    #[test]
    fn init_rejects_bad_secret_length() {
        let spk = generate_identity_keypair();
        let err = initialize_double_ratchet(
            &[0u8; 16],
            ad(),
            RatchetRole::Initiator {
                remote_spk_public: &spk.public_key,
            },
        )
        .unwrap_err();
        assert!(matches!(err, SignalError::InvalidInput(_)));
    }

    #[test]
    fn init_rejects_empty_ad() {
        let spk = generate_identity_keypair();
        let err = initialize_double_ratchet(
            &shared_secret(),
            b"",
            RatchetRole::Initiator {
                remote_spk_public: &spk.public_key,
            },
        )
        .unwrap_err();
        assert!(matches!(err, SignalError::InvalidInput(_)));
    }

    #[test]
    fn init_rejects_bad_spk_length() {
        let err = initialize_double_ratchet(
            &shared_secret(),
            ad(),
            RatchetRole::Initiator {
                remote_spk_public: &[0u8; 16],
            },
        )
        .unwrap_err();
        assert!(matches!(err, SignalError::InvalidInput(_)));
    }

    #[test]
    fn encrypt_without_chain_fails() {
        let (_, mut bob) = pair();
        let err = double_ratchet_encrypt_internal(&mut bob, b"hi").unwrap_err();
        assert!(matches!(err, SignalError::InvalidInput(_)));
    }

    #[test]
    fn roundtrip_alice_to_bob() {
        let (mut alice, mut bob) = pair();
        let msg = double_ratchet_encrypt_internal(&mut alice, b"hello bob").unwrap();
        let plain = double_ratchet_decrypt_internal(&mut bob, &msg).unwrap();
        assert_eq!(plain, b"hello bob");
    }

    #[test]
    fn bidirectional_messaging() {
        let (mut alice, mut bob) = pair();

        let m1 = double_ratchet_encrypt_internal(&mut alice, b"ping").unwrap();
        assert_eq!(
            double_ratchet_decrypt_internal(&mut bob, &m1).unwrap(),
            b"ping"
        );

        let m2 = double_ratchet_encrypt_internal(&mut bob, b"pong").unwrap();
        assert_eq!(
            double_ratchet_decrypt_internal(&mut alice, &m2).unwrap(),
            b"pong"
        );

        let m3 = double_ratchet_encrypt_internal(&mut alice, b"again").unwrap();
        assert_eq!(
            double_ratchet_decrypt_internal(&mut bob, &m3).unwrap(),
            b"again"
        );
    }

    #[test]
    fn out_of_order_skipped_keys() {
        let (mut alice, mut bob) = pair();

        let m0 = double_ratchet_encrypt_internal(&mut alice, b"msg0").unwrap();
        let m1 = double_ratchet_encrypt_internal(&mut alice, b"msg1").unwrap();
        let m2 = double_ratchet_encrypt_internal(&mut alice, b"msg2").unwrap();

        assert_eq!(
            double_ratchet_decrypt_internal(&mut bob, &m2).unwrap(),
            b"msg2"
        );
        assert_eq!(
            double_ratchet_decrypt_internal(&mut bob, &m0).unwrap(),
            b"msg0"
        );
        assert_eq!(
            double_ratchet_decrypt_internal(&mut bob, &m1).unwrap(),
            b"msg1"
        );
    }

    #[test]
    fn skip_message_keys_too_many() {
        let (_, mut bob) = pair();
        bob.receiving_chain_key = Some(vec![1u8; 32]);
        bob.receiving_dh_public_key = Some(vec![2u8; 32]);
        bob.receiving_message_number = 0;
        let err = skip_message_keys(&mut bob, (MAX_SKIP_PER_CHAIN as u32) + 1).unwrap_err();
        assert!(matches!(err, SignalError::InvalidInput(_)));
    }

    #[test]
    fn skip_message_keys_noop_paths() {
        let (_, mut bob) = pair();
        bob.receiving_message_number = 5;
        assert!(skip_message_keys(&mut bob, 5).is_ok());
        bob.receiving_message_number = 0;
        bob.receiving_chain_key = None;
        assert!(skip_message_keys(&mut bob, 3).is_ok());
    }

    #[test]
    fn skip_without_dh_public_is_noop() {
        let (_, mut bob) = pair();
        bob.receiving_chain_key = Some(vec![3u8; 32]);
        bob.receiving_dh_public_key = None;
        bob.receiving_message_number = 0;
        skip_message_keys(&mut bob, 2).unwrap();
        assert!(bob.skipped_message_keys.is_empty());
    }

    #[test]
    fn cleanup_skipped_message_keys_fifo() {
        let (mut alice, mut bob) = pair();
        let msgs: Vec<_> = (0..5)
            .map(|i| {
                double_ratchet_encrypt_internal(&mut alice, format!("m{i}").as_bytes()).unwrap()
            })
            .collect();
        double_ratchet_decrypt_internal(&mut bob, &msgs[4]).unwrap();
        assert!(bob.skipped_message_keys.len() >= 4);
        assert_eq!(cleanup_skipped_message_keys_internal(&mut bob, 100), 0);
        let before = bob.skipped_message_keys.len();
        let oldest = bob.skipped_key_order.first().cloned();
        let removed = cleanup_skipped_message_keys_internal(&mut bob, 2);
        assert_eq!(removed, before - 2);
        assert_eq!(bob.skipped_message_keys.len(), 2);
        if let Some(id) = oldest {
            assert!(!bob.skipped_message_keys.contains_key(&id));
        }
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails_without_commit() {
        let (mut alice, mut bob) = pair();
        let root_before = bob.root_key.clone();
        let mut msg = double_ratchet_encrypt_internal(&mut alice, b"secret").unwrap();
        if let Some(b) = msg.ciphertext.last_mut() {
            *b ^= 0xff;
        }
        let err = double_ratchet_decrypt_internal(&mut bob, &msg).unwrap_err();
        assert!(matches!(err, SignalError::Decryption(_)));
        assert_eq!(bob.root_key, root_before);
        assert!(bob.receiving_chain_key.is_none());
    }

    #[test]
    fn decrypt_short_ciphertext_fails() {
        let (mut alice, mut bob) = pair();
        let mut msg = double_ratchet_encrypt_internal(&mut alice, b"x").unwrap();
        msg.ciphertext = vec![1u8; 8];
        let err = double_ratchet_decrypt_internal(&mut bob, &msg).unwrap_err();
        assert!(matches!(err, SignalError::Decryption(_)));
    }

    #[test]
    fn decrypt_message_number_mismatch() {
        let (mut alice, mut bob) = pair();
        let msg = double_ratchet_encrypt_internal(&mut alice, b"a").unwrap();
        double_ratchet_decrypt_internal(&mut bob, &msg).unwrap();
        let err = double_ratchet_decrypt_internal(&mut bob, &msg).unwrap_err();
        assert!(matches!(
            err,
            SignalError::InvalidInput(_) | SignalError::Decryption(_)
        ));
    }

    #[test]
    fn decrypt_missing_receiving_chain_key() {
        let (_, mut bob) = pair();
        bob.receiving_dh_public_key = Some(vec![9u8; 32]);
        bob.receiving_chain_key = None;
        bob.receiving_message_number = 0;
        let msg = DoubleRatchetMessage {
            ciphertext: vec![0u8; 28],
            dh_public_key: vec![9u8; 32],
            message_number: 0,
            previous_chain_length: 0,
        };
        let err = double_ratchet_decrypt_internal(&mut bob, &msg).unwrap_err();
        assert!(matches!(err, SignalError::InvalidInput(_)));
    }

    #[test]
    fn perform_dh_without_prior_sending_keypair_fails() {
        let mut bob = DoubleRatchetState::new();
        bob.root_key = shared_secret().to_vec();
        bob.sending_dh_keypair = None;
        let remote = generate_identity_keypair();
        let err = perform_dh_ratchet_step(&mut bob, &remote.public_key).unwrap_err();
        assert!(matches!(err, SignalError::InvalidInput(_)));
    }

    #[test]
    fn perform_dh_with_existing_sending_keypair() {
        let (mut alice, _) = pair();
        assert!(alice.sending_dh_keypair.is_some());
        let remote = generate_identity_keypair();
        let before = alice.root_key.clone();
        perform_dh_ratchet_step(&mut alice, &remote.public_key).unwrap();
        assert_ne!(alice.root_key, before);
    }

    #[test]
    fn aead_decrypt_tag_too_short() {
        let err = aead_decrypt(&[0u8; 32], &[0u8; 8], &[0u8; 12], b"").unwrap_err();
        assert!(matches!(err, SignalError::Decryption(_)));
    }

    #[test]
    fn derive_helpers() {
        let ck = [9u8; 32];
        assert_eq!(derive_message_key(&ck).unwrap().len(), 32);
        assert_eq!(derive_next_chain_key(&ck).unwrap().len(), 32);
    }

    #[test]
    fn encrypt_without_dh_keypair_fails() {
        let (mut state, _) = pair();
        state.sending_dh_keypair = None;
        let err = double_ratchet_encrypt_internal(&mut state, b"x").unwrap_err();
        assert!(matches!(err, SignalError::InvalidInput(_)));
    }

    #[test]
    fn initiator_with_remote_spk_uses_dh_chain() {
        let bob_spk = generate_identity_keypair();
        let alice = initialize_double_ratchet(
            &shared_secret(),
            b"ad",
            RatchetRole::Initiator {
                remote_spk_public: &bob_spk.public_key,
            },
        )
        .unwrap();
        assert_eq!(alice.associated_data, b"ad");
        assert_eq!(
            alice.receiving_dh_public_key.as_deref(),
            Some(bob_spk.public_key.as_slice())
        );
        assert!(alice.sending_chain_key.is_some());
    }

    #[test]
    fn forged_large_pn_does_not_mutate_skipped_keys() {
        let (mut alice, mut bob) = pair();
        let m0 = double_ratchet_encrypt_internal(&mut alice, b"hello").unwrap();
        double_ratchet_decrypt_internal(&mut bob, &m0).unwrap();
        let skipped_before = bob.skipped_message_keys.clone();
        let order_before = bob.skipped_key_order.clone();
        let forged = DoubleRatchetMessage {
            ciphertext: vec![0u8; 40],
            dh_public_key: generate_identity_keypair().public_key,
            message_number: 0,
            previous_chain_length: 500,
        };
        assert!(double_ratchet_decrypt_internal(&mut bob, &forged).is_err());
        assert_eq!(bob.skipped_message_keys, skipped_before);
        assert_eq!(bob.skipped_key_order, order_before);
    }
}
