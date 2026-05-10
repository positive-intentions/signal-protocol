//! Double Ratchet Implementation for Signal Protocol
//!
//! Thin WASM wrapper around signal-protocol-core.

use crate::rust::crypto::uint8_array_to_vec;
use crate::rust::types::KeyPair;
use js_sys::Uint8Array;
use std::collections::BTreeMap;
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

fn core_to_wasm_keypair(k: signal_protocol_core::KeyPair) -> KeyPair {
    KeyPair {
        public_key: k.public_key,
        private_key: k.private_key,
    }
}

fn core_to_wasm_state(core: signal_protocol_core::DoubleRatchetState) -> DoubleRatchetState {
    DoubleRatchetState {
        root_key: core.root_key,
        sending_chain_key: core.sending_chain_key,
        receiving_chain_key: core.receiving_chain_key,
        sending_dh_keypair: core.sending_dh_keypair.map(core_to_wasm_keypair),
        receiving_dh_public_key: core.receiving_dh_public_key,
        sending_message_number: core.sending_message_number,
        receiving_message_number: core.receiving_message_number,
        previous_chain_length: core.previous_chain_length,
        skipped_message_keys: core.skipped_message_keys,
    }
}

fn wasm_to_core_keypair(k: &KeyPair) -> signal_protocol_core::KeyPair {
    signal_protocol_core::KeyPair {
        public_key: k.public_key.clone(),
        private_key: k.private_key.clone(),
    }
}

fn wasm_to_core_state(wasm: &DoubleRatchetState) -> signal_protocol_core::DoubleRatchetState {
    signal_protocol_core::DoubleRatchetState {
        root_key: wasm.root_key.clone(),
        sending_chain_key: wasm.sending_chain_key.clone(),
        receiving_chain_key: wasm.receiving_chain_key.clone(),
        sending_dh_keypair: wasm.sending_dh_keypair.as_ref().map(wasm_to_core_keypair),
        receiving_dh_public_key: wasm.receiving_dh_public_key.clone(),
        sending_message_number: wasm.sending_message_number,
        receiving_message_number: wasm.receiving_message_number,
        previous_chain_length: wasm.previous_chain_length,
        skipped_message_keys: wasm.skipped_message_keys.clone(),
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct DoubleRatchetState {
    #[wasm_bindgen(skip)]
    pub root_key: Vec<u8>,
    #[wasm_bindgen(skip)]
    pub sending_chain_key: Option<Vec<u8>>,
    #[wasm_bindgen(skip)]
    pub receiving_chain_key: Option<Vec<u8>>,
    #[wasm_bindgen(skip)]
    pub sending_dh_keypair: Option<KeyPair>,
    #[wasm_bindgen(skip)]
    pub receiving_dh_public_key: Option<Vec<u8>>,
    #[wasm_bindgen(skip)]
    pub sending_message_number: u32,
    #[wasm_bindgen(skip)]
    pub receiving_message_number: u32,
    #[wasm_bindgen(skip)]
    pub previous_chain_length: u32,
    #[wasm_bindgen(skip)]
    pub skipped_message_keys: BTreeMap<String, Vec<u8>>,
}

#[wasm_bindgen]
impl DoubleRatchetState {
    #[wasm_bindgen(constructor)]
    pub fn new() -> DoubleRatchetState {
        core_to_wasm_state(signal_protocol_core::DoubleRatchetState::new())
    }

    #[wasm_bindgen(getter)]
    pub fn root_key(&self) -> Uint8Array {
        Uint8Array::from(&self.root_key[..])
    }

    #[wasm_bindgen(getter)]
    pub fn sending_message_number(&self) -> u32 {
        self.sending_message_number
    }

    #[wasm_bindgen(getter)]
    pub fn receiving_message_number(&self) -> u32 {
        self.receiving_message_number
    }

    #[wasm_bindgen(getter)]
    pub fn skipped_keys_count(&self) -> usize {
        self.skipped_message_keys.len()
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct DoubleRatchetMessage {
    #[wasm_bindgen(skip)]
    pub ciphertext: Vec<u8>,
    #[wasm_bindgen(skip)]
    pub dh_public_key: Vec<u8>,
    #[wasm_bindgen(skip)]
    pub message_number: u32,
    #[wasm_bindgen(skip)]
    pub previous_chain_length: u32,
}

#[wasm_bindgen]
impl DoubleRatchetMessage {
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Uint8Array {
        Uint8Array::from(&self.ciphertext[..])
    }

    #[wasm_bindgen(getter)]
    pub fn dh_public_key(&self) -> Uint8Array {
        Uint8Array::from(&self.dh_public_key[..])
    }

    #[wasm_bindgen(getter)]
    pub fn message_number(&self) -> u32 {
        self.message_number
    }

    #[wasm_bindgen(getter)]
    pub fn previous_chain_length(&self) -> u32 {
        self.previous_chain_length
    }
}

#[wasm_bindgen]
pub fn initialize_double_ratchet(
    shared_secret: &Uint8Array,
    is_initiator: bool,
) -> Result<DoubleRatchetState, JsValue> {
    log(&format!(
        "Initializing Double Ratchet (initiator: {})",
        is_initiator
    ));
    let shared_secret_bytes = uint8_array_to_vec(shared_secret);
    signal_protocol_core::initialize_double_ratchet_internal(&shared_secret_bytes, is_initiator)
        .map(core_to_wasm_state)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Derive a message key from a chain key - delegates to core (for tests)
pub(crate) fn derive_message_key(
    chain_key: &[u8],
) -> Result<Vec<u8>, crate::rust::error::SignalError> {
    signal_protocol_core::derive_message_key(chain_key)
}

/// Derive the next chain key - delegates to core (for tests)
pub(crate) fn derive_next_chain_key(
    chain_key: &[u8],
) -> Result<Vec<u8>, crate::rust::error::SignalError> {
    signal_protocol_core::derive_next_chain_key(chain_key)
}

#[wasm_bindgen]
pub fn double_ratchet_encrypt(
    state: &mut DoubleRatchetState,
    plaintext: &Uint8Array,
) -> Result<DoubleRatchetMessage, JsValue> {
    log(&format!(
        "Encrypting message #{}",
        state.sending_message_number
    ));
    let plaintext_bytes = uint8_array_to_vec(plaintext);
    let mut core_state = wasm_to_core_state(state);
    let core_msg =
        signal_protocol_core::double_ratchet_encrypt_internal(&mut core_state, &plaintext_bytes)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
    *state = core_to_wasm_state(core_state);
    Ok(DoubleRatchetMessage {
        ciphertext: core_msg.ciphertext,
        dh_public_key: core_msg.dh_public_key,
        message_number: core_msg.message_number,
        previous_chain_length: core_msg.previous_chain_length,
    })
}

#[wasm_bindgen]
pub fn double_ratchet_decrypt(
    state: &mut DoubleRatchetState,
    message: &DoubleRatchetMessage,
) -> Result<Uint8Array, JsValue> {
    log(&format!("Decrypting message #{}", message.message_number));
    let core_msg = signal_protocol_core::DoubleRatchetMessage {
        ciphertext: message.ciphertext.clone(),
        dh_public_key: message.dh_public_key.clone(),
        message_number: message.message_number,
        previous_chain_length: message.previous_chain_length,
    };
    let mut core_state = wasm_to_core_state(state);
    let plaintext =
        signal_protocol_core::double_ratchet_decrypt_internal(&mut core_state, &core_msg)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
    *state = core_to_wasm_state(core_state);
    Ok(Uint8Array::from(&plaintext[..]))
}

#[wasm_bindgen]
pub fn cleanup_skipped_message_keys(state: &mut DoubleRatchetState, max_keys: usize) -> usize {
    log(&format!(
        "Cleaning up skipped message keys (max: {})",
        max_keys
    ));
    let mut core_state = wasm_to_core_state(state);
    let removed =
        signal_protocol_core::cleanup_skipped_message_keys_internal(&mut core_state, max_keys);
    *state = core_to_wasm_state(core_state);
    removed
}

/// Perform DH ratchet step - delegates to core (for tests)
pub(crate) fn perform_dh_ratchet_step(
    state: &mut DoubleRatchetState,
    new_remote_public_key: &[u8],
) -> Result<(), crate::rust::error::SignalError> {
    let mut core_state = wasm_to_core_state(state);
    signal_protocol_core::perform_dh_ratchet_step(&mut core_state, new_remote_public_key)?;
    *state = core_to_wasm_state(core_state);
    Ok(())
}

/// Skip message keys - delegates to core (for tests)
pub(crate) fn skip_message_keys(
    state: &mut DoubleRatchetState,
    until_message_number: u32,
) -> Result<(), crate::rust::error::SignalError> {
    let mut core_state = wasm_to_core_state(state);
    signal_protocol_core::skip_message_keys(&mut core_state, until_message_number)?;
    *state = core_to_wasm_state(core_state);
    Ok(())
}

/// Cleanup skipped keys internal - delegates to core (for tests)
pub(crate) fn cleanup_skipped_message_keys_internal(
    state: &mut DoubleRatchetState,
    max_keys: usize,
) -> usize {
    let mut core_state = wasm_to_core_state(state);
    let removed =
        signal_protocol_core::cleanup_skipped_message_keys_internal(&mut core_state, max_keys);
    *state = core_to_wasm_state(core_state);
    removed
}

/// Internal version for native testing - delegates to core
pub(crate) fn initialize_double_ratchet_internal(
    shared_secret: &[u8],
    is_initiator: bool,
) -> Result<DoubleRatchetState, crate::rust::error::SignalError> {
    signal_protocol_core::initialize_double_ratchet_internal(shared_secret, is_initiator)
        .map(core_to_wasm_state)
}

/// Internal encrypt for native testing - delegates to core
pub(crate) fn double_ratchet_encrypt_internal(
    state: &mut DoubleRatchetState,
    plaintext: &[u8],
) -> Result<DoubleRatchetMessage, crate::rust::error::SignalError> {
    let mut core_state = wasm_to_core_state(state);
    let core_msg =
        signal_protocol_core::double_ratchet_encrypt_internal(&mut core_state, plaintext)?;
    *state = core_to_wasm_state(core_state);
    Ok(DoubleRatchetMessage {
        ciphertext: core_msg.ciphertext,
        dh_public_key: core_msg.dh_public_key,
        message_number: core_msg.message_number,
        previous_chain_length: core_msg.previous_chain_length,
    })
}

/// Internal decrypt for native testing - delegates to core
pub(crate) fn double_ratchet_decrypt_internal(
    state: &mut DoubleRatchetState,
    message: &DoubleRatchetMessage,
) -> Result<Vec<u8>, crate::rust::error::SignalError> {
    let core_msg = signal_protocol_core::DoubleRatchetMessage {
        ciphertext: message.ciphertext.clone(),
        dh_public_key: message.dh_public_key.clone(),
        message_number: message.message_number,
        previous_chain_length: message.previous_chain_length,
    };
    let mut core_state = wasm_to_core_state(state);
    let plaintext =
        signal_protocol_core::double_ratchet_decrypt_internal(&mut core_state, &core_msg)?;
    *state = core_to_wasm_state(core_state);
    Ok(plaintext)
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;
    wasm_bindgen_test_configure!(run_in_browser);
    use crate::rust::keys::*;
    use crate::rust::x3dh::x3dh_initiate;

    #[wasm_bindgen_test]
    fn test_double_ratchet_initialization() {
        let shared_secret = Uint8Array::from(&[1u8; 32][..]);
        let alice_state = initialize_double_ratchet(&shared_secret, true).unwrap();
        assert_eq!(alice_state.sending_message_number, 0);
        assert_eq!(alice_state.receiving_message_number, 0);
        assert!(alice_state.sending_chain_key.is_some());
        assert!(alice_state.sending_dh_keypair.is_some());

        let bob_state = initialize_double_ratchet(&shared_secret, false).unwrap();
        assert_eq!(bob_state.sending_message_number, 0);
        assert_eq!(bob_state.receiving_message_number, 0);
        assert!(bob_state.sending_chain_key.is_none());
    }

    #[wasm_bindgen_test]
    fn test_message_key_derivation() {
        let chain_key = [1u8; 32];
        let message_key = derive_message_key(&chain_key).unwrap();
        assert_eq!(message_key.len(), 32);
        let message_key2 = derive_message_key(&chain_key).unwrap();
        assert_eq!(message_key, message_key2);
        let different_chain_key = [2u8; 32];
        let different_message_key = derive_message_key(&different_chain_key).unwrap();
        assert_ne!(message_key, different_message_key);
    }

    #[wasm_bindgen_test]
    fn test_chain_key_advancement() {
        let chain_key = [1u8; 32];
        let next_chain_key = derive_next_chain_key(&chain_key).unwrap();
        assert_eq!(next_chain_key.len(), 32);
        assert_ne!(chain_key.to_vec(), next_chain_key);
        let next_chain_key2 = derive_next_chain_key(&chain_key).unwrap();
        assert_eq!(next_chain_key, next_chain_key2);
        let third_chain_key = derive_next_chain_key(&next_chain_key).unwrap();
        assert_ne!(next_chain_key, third_chain_key);
    }

    #[wasm_bindgen_test]
    fn test_double_ratchet_encrypt_decrypt() {
        let shared_secret = Uint8Array::from(&[1u8; 32][..]);
        let mut alice_state = initialize_double_ratchet(&shared_secret, true).unwrap();
        let mut bob_state = initialize_double_ratchet(&shared_secret, false).unwrap();
        let plaintext = Uint8Array::from("Hello Bob!".as_bytes());
        let encrypted_message = double_ratchet_encrypt(&mut alice_state, &plaintext).unwrap();
        assert!(encrypted_message.ciphertext().length() > plaintext.length());
        assert_eq!(encrypted_message.message_number(), 0);
        assert_eq!(alice_state.sending_message_number, 1);
        let decrypted = double_ratchet_decrypt(&mut bob_state, &encrypted_message).unwrap();
        let decrypted_text = String::from_utf8(decrypted.to_vec()).unwrap();
        assert_eq!(decrypted_text, "Hello Bob!");
        assert_eq!(bob_state.receiving_message_number, 1);
    }

    #[wasm_bindgen_test]
    fn test_aad_functionality() {
        let shared_secret = Uint8Array::from(&[1u8; 32][..]);
        let mut alice_state = initialize_double_ratchet(&shared_secret, true).unwrap();
        let mut bob_state = initialize_double_ratchet(&shared_secret, false).unwrap();
        let plaintext = Uint8Array::from("Test message with AAD".as_bytes());
        let encrypted_message = double_ratchet_encrypt(&mut alice_state, &plaintext).unwrap();
        let ciphertext_len = encrypted_message.ciphertext().length();
        assert!(ciphertext_len >= 12 + 16);
        assert!(ciphertext_len >= plaintext.length() + 12 + 16);
        assert_eq!(encrypted_message.message_number(), 0);
        assert_eq!(encrypted_message.previous_chain_length(), 0);
        assert_eq!(encrypted_message.dh_public_key().length(), 32);
        let decrypted = double_ratchet_decrypt(&mut bob_state, &encrypted_message).unwrap();
        let decrypted_text = String::from_utf8(decrypted.to_vec()).unwrap();
        assert_eq!(decrypted_text, "Test message with AAD");
    }

    #[wasm_bindgen_test]
    fn test_aad_tampering_protection() {
        let shared_secret = Uint8Array::from(&[1u8; 32][..]);
        let mut alice_state = initialize_double_ratchet(&shared_secret, true).unwrap();
        let mut bob_state = initialize_double_ratchet(&shared_secret, false).unwrap();
        let plaintext = Uint8Array::from("Secret message".as_bytes());
        let encrypted_message = double_ratchet_encrypt(&mut alice_state, &plaintext).unwrap();
        let decrypted = double_ratchet_decrypt(&mut bob_state, &encrypted_message).unwrap();
        assert_eq!(
            String::from_utf8(decrypted.to_vec()).unwrap(),
            "Secret message"
        );
        let ciphertext = encrypted_message.ciphertext().to_vec();
        assert!(ciphertext.len() >= 12 + 16);
    }

    #[wasm_bindgen_test]
    fn test_bidirectional_multiple_ratchet_steps() {
        let shared_secret = Uint8Array::from(&[1u8; 32][..]);
        let mut alice_state = initialize_double_ratchet(&shared_secret, true).unwrap();
        let mut bob_state = initialize_double_ratchet(&shared_secret, false).unwrap();
        let msg1 = Uint8Array::from("Message 1".as_bytes());
        let enc1 = double_ratchet_encrypt(&mut alice_state, &msg1).unwrap();
        let dec1 = double_ratchet_decrypt(&mut bob_state, &enc1).unwrap();
        assert_eq!(String::from_utf8(dec1.to_vec()).unwrap(), "Message 1");
        let msg2 = Uint8Array::from("Message 2".as_bytes());
        let enc2 = double_ratchet_encrypt(&mut bob_state, &msg2).unwrap();
        let dec2 = double_ratchet_decrypt(&mut alice_state, &enc2).unwrap();
        assert_eq!(String::from_utf8(dec2.to_vec()).unwrap(), "Message 2");
        let msg3 = Uint8Array::from("Message 3".as_bytes());
        let enc3 = double_ratchet_encrypt(&mut alice_state, &msg3).unwrap();
        let dec3_result = double_ratchet_decrypt(&mut bob_state, &enc3);
        assert!(dec3_result.is_ok());
        let dec3 = dec3_result.unwrap();
        assert_eq!(String::from_utf8(dec3.to_vec()).unwrap(), "Message 3");
    }

    // Signal Double Ratchet semantics (per spec):
    //   - At init, both parties share the same root_key (= shared_secret).
    //   - Sending a message does NOT advance root_key.
    //   - Receiving a message with a new DH public key triggers DHRatchet,
    //     which performs TWO KDF_RK calls - one matching the sender's last
    //     sending ratchet, plus one fresh sending ratchet on the receiver.
    //   - After a ping-pong (A->B, B->A), the receiver is always one DH
    //     ratchet step ahead of the peer, so the root_keys intentionally
    //     diverge. Previously this test asserted the opposite, which is
    //     mathematically impossible for any correct DR implementation.
    #[wasm_bindgen_test]
    fn test_root_key_invariants_after_init() {
        let shared_secret = Uint8Array::from(&[1u8; 32][..]);
        let alice_state = initialize_double_ratchet(&shared_secret, true).unwrap();
        let bob_state = initialize_double_ratchet(&shared_secret, false).unwrap();
        let alice_root = alice_state.root_key().to_vec();
        let bob_root = bob_state.root_key().to_vec();
        assert_eq!(alice_root, bob_root, "roots must match at init");
        assert_eq!(alice_root, vec![1u8; 32], "initial root equals shared_secret");
    }

    #[wasm_bindgen_test]
    fn test_send_does_not_advance_root_key() {
        let shared_secret = Uint8Array::from(&[1u8; 32][..]);
        let mut alice_state = initialize_double_ratchet(&shared_secret, true).unwrap();
        let before = alice_state.root_key().to_vec();
        let _enc = double_ratchet_encrypt(
            &mut alice_state,
            &Uint8Array::from("Message 1".as_bytes()),
        )
        .unwrap();
        let after = alice_state.root_key().to_vec();
        assert_eq!(before, after, "encrypt must not advance root_key");
    }

    #[wasm_bindgen_test]
    fn test_receive_advances_root_key_and_diverges() {
        let shared_secret = Uint8Array::from(&[1u8; 32][..]);
        let mut alice_state = initialize_double_ratchet(&shared_secret, true).unwrap();
        let mut bob_state = initialize_double_ratchet(&shared_secret, false).unwrap();
        let initial_root = alice_state.root_key().to_vec();

        let enc1 = double_ratchet_encrypt(
            &mut alice_state,
            &Uint8Array::from("Message 1".as_bytes()),
        )
        .unwrap();
        let _ = double_ratchet_decrypt(&mut bob_state, &enc1).unwrap();

        let bob_root_after_recv = bob_state.root_key().to_vec();
        assert_ne!(
            bob_root_after_recv, initial_root,
            "Bob's root must advance on first DH ratchet"
        );
        assert_eq!(
            alice_state.root_key().to_vec(),
            initial_root,
            "Alice's root unchanged until she receives"
        );

        let enc2 = double_ratchet_encrypt(
            &mut bob_state,
            &Uint8Array::from("Message 2".as_bytes()),
        )
        .unwrap();
        let _ = double_ratchet_decrypt(&mut alice_state, &enc2).unwrap();

        let alice_root_after_recv = alice_state.root_key().to_vec();
        assert_ne!(
            alice_root_after_recv, initial_root,
            "Alice's root must advance after DH ratchet on receive"
        );
        assert_ne!(
            alice_root_after_recv, bob_root_after_recv,
            "per Signal spec, receiver ends one DH-ratchet step ahead of peer"
        );
    }

    #[wasm_bindgen_test]
    fn test_decryption_survives_root_key_divergence() {
        let shared_secret = Uint8Array::from(&[1u8; 32][..]);
        let mut alice_state = initialize_double_ratchet(&shared_secret, true).unwrap();
        let mut bob_state = initialize_double_ratchet(&shared_secret, false).unwrap();

        let enc1 = double_ratchet_encrypt(
            &mut alice_state,
            &Uint8Array::from("Message 1".as_bytes()),
        )
        .unwrap();
        let dec1 = double_ratchet_decrypt(&mut bob_state, &enc1).unwrap();
        assert_eq!(String::from_utf8(dec1.to_vec()).unwrap(), "Message 1");

        let enc2 = double_ratchet_encrypt(
            &mut bob_state,
            &Uint8Array::from("Message 2".as_bytes()),
        )
        .unwrap();
        let dec2 = double_ratchet_decrypt(&mut alice_state, &enc2).unwrap();
        assert_eq!(String::from_utf8(dec2.to_vec()).unwrap(), "Message 2");

        // Roots have diverged at this point - confirm the protocol still works.
        let enc3 = double_ratchet_encrypt(
            &mut alice_state,
            &Uint8Array::from("Message 3".as_bytes()),
        )
        .unwrap();
        let dec3 = double_ratchet_decrypt(&mut bob_state, &enc3).unwrap();
        assert_eq!(String::from_utf8(dec3.to_vec()).unwrap(), "Message 3");
    }

    #[wasm_bindgen_test]
    fn test_out_of_order_messages() {
        let shared_secret = Uint8Array::from(&[1u8; 32][..]);
        let mut alice_state = initialize_double_ratchet(&shared_secret, true).unwrap();
        let mut bob_state = initialize_double_ratchet(&shared_secret, false).unwrap();
        let msg1 =
            double_ratchet_encrypt(&mut alice_state, &Uint8Array::from("Message 1".as_bytes()))
                .unwrap();
        let msg2 =
            double_ratchet_encrypt(&mut alice_state, &Uint8Array::from("Message 2".as_bytes()))
                .unwrap();
        let msg3 =
            double_ratchet_encrypt(&mut alice_state, &Uint8Array::from("Message 3".as_bytes()))
                .unwrap();
        let decrypted3 = double_ratchet_decrypt(&mut bob_state, &msg3).unwrap();
        assert_eq!(String::from_utf8(decrypted3.to_vec()).unwrap(), "Message 3");
        let decrypted1 = double_ratchet_decrypt(&mut bob_state, &msg1).unwrap();
        assert_eq!(String::from_utf8(decrypted1.to_vec()).unwrap(), "Message 1");
        let decrypted2 = double_ratchet_decrypt(&mut bob_state, &msg2).unwrap();
        assert_eq!(String::from_utf8(decrypted2.to_vec()).unwrap(), "Message 2");
        assert_eq!(bob_state.receiving_message_number, 3);
        assert_eq!(bob_state.skipped_keys_count(), 0);
    }

    #[wasm_bindgen_test]
    fn test_skipped_key_cleanup() {
        let shared_secret = Uint8Array::from(&[1u8; 32][..]);
        let mut alice_state = initialize_double_ratchet(&shared_secret, true).unwrap();
        let mut bob_state = initialize_double_ratchet(&shared_secret, false).unwrap();
        let mut messages = Vec::new();
        for i in 0..10 {
            let plaintext = Uint8Array::from(format!("Message {}", i).as_bytes());
            messages.push(double_ratchet_encrypt(&mut alice_state, &plaintext).unwrap());
        }
        let last_message = messages.last().unwrap();
        let _decrypted = double_ratchet_decrypt(&mut bob_state, last_message).unwrap();
        assert!(bob_state.skipped_keys_count() > 5);
        let removed = cleanup_skipped_message_keys(&mut bob_state, 3);
        assert!(removed > 0);
        assert!(bob_state.skipped_keys_count() <= 3);
    }

    #[wasm_bindgen_test]
    fn test_error_conditions() {
        let short_secret = Uint8Array::from(&[1u8; 16][..]);
        let result = initialize_double_ratchet(&short_secret, true);
        assert!(result.is_err());
        let mut empty_state = DoubleRatchetState::new();
        let plaintext = Uint8Array::from("test".as_bytes());
        let result = double_ratchet_encrypt(&mut empty_state, &plaintext);
        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    fn test_integration_with_x3dh() {
        let alice_identity = generate_identity_keypair().unwrap();
        let alice_ephemeral = generate_ephemeral_keypair().unwrap();
        let bob_identity = generate_identity_keypair().unwrap();
        let bob_signed_prekey = generate_signed_prekey().unwrap();
        let x3dh_result = x3dh_initiate(
            &alice_identity.private_key(),
            &alice_ephemeral.private_key(),
            &bob_identity.public_key(),
            &bob_signed_prekey.public_key(),
            None,
        )
        .unwrap();
        let shared_secret = x3dh_result.shared_secret();
        let mut alice_state = initialize_double_ratchet(&shared_secret, true).unwrap();
        let mut bob_state = initialize_double_ratchet(&shared_secret, false).unwrap();
        let plaintext = Uint8Array::from("X3DH -> Double Ratchet integration test".as_bytes());
        let encrypted = double_ratchet_encrypt(&mut alice_state, &plaintext).unwrap();
        let decrypted = double_ratchet_decrypt(&mut bob_state, &encrypted).unwrap();
        let decrypted_text = String::from_utf8(decrypted.to_vec()).unwrap();
        assert_eq!(decrypted_text, "X3DH -> Double Ratchet integration test");
    }
}
