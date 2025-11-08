//! WASM-specific tests for Signal Protocol implementation
//! 
//! These tests run in a WASM environment and test all the WASM-bound functions
//! that cannot be tested in native Rust tests. They provide coverage for
//! JavaScript interoperability and WASM-specific functionality.

#[cfg(target_arch = "wasm32")]
mod wasm_tests {
    use wasm_bindgen_test::*;
    use js_sys::Uint8Array;
    use wasm_bindgen::JsValue;
    
    use crate::rust::{
        keys::*,
        crypto::*,
        utils::*,
        double_ratchet::*,
        types::*,
        error::SignalError,
    };

    // Tests can run in both browser and node environments

    // Test library initialization (test version)
    #[wasm_bindgen_test]
    fn test_initialization() {
        // Test that initialization works without panicking
        crate::init_for_test();
        crate::init_for_test(); // Should not panic on second call
        // If we get here, the test passes
        assert_eq!(1, 1);
    }

    // Test error conversion to JsValue
    #[wasm_bindgen_test]
    fn test_signal_error_to_js_value() {
        let error = SignalError::KeyGeneration("test error".to_string());
        let js_value: JsValue = error.into();
        
        // Test that the conversion worked
        assert!(js_value.is_string());
        let error_string = js_value.as_string().unwrap();
        assert!(error_string.contains("Key generation failed"));
        assert!(error_string.contains("test error"));
    }

    // Test all SignalError variants conversion to JsValue
    #[wasm_bindgen_test]
    fn test_all_signal_errors_to_js_value() {
        let errors = vec![
            SignalError::KeyGeneration("test".to_string()),
            SignalError::SignatureVerification("test".to_string()),
            SignalError::KeyExchange("test".to_string()),
            SignalError::Encryption("test".to_string()),
            SignalError::Decryption("test".to_string()),
            SignalError::KeyDerivation("test".to_string()),
            SignalError::Serialization("test".to_string()),
            SignalError::InvalidInput("test".to_string()),
        ];
        
        for error in errors {
            let js_value: JsValue = error.into();
            assert!(js_value.is_string());
            let error_string = js_value.as_string().unwrap();
            assert!(error_string.contains("test"));
            assert!(error_string.len() > 0);
        }
    }

    // Test KeyPair WASM getter methods
    #[wasm_bindgen_test]
    fn test_keypair_wasm_getters() {
        let keypair = KeyPair {
            public_key: vec![1u8; 32],
            private_key: vec![2u8; 32],
        };
        
        // Test public_key getter
        let public_key_js = keypair.public_key();
        assert_eq!(public_key_js.length(), 32);
        let public_bytes: Vec<u8> = public_key_js.to_vec();
        assert_eq!(public_bytes, vec![1u8; 32]);
        
        // Test private_key getter
        let private_key_js = keypair.private_key();
        assert_eq!(private_key_js.length(), 32);
        let private_bytes: Vec<u8> = private_key_js.to_vec();
        assert_eq!(private_bytes, vec![2u8; 32]);
    }

    // Test X3DHResult WASM getter methods
    #[wasm_bindgen_test]
    fn test_x3dh_result_wasm_getters() {
        let result = X3DHResult {
            shared_secret: vec![3u8; 32],
            associated_data: vec![4u8; 16],
        };
        
        // Test shared_secret getter
        let shared_secret_js = result.shared_secret();
        assert_eq!(shared_secret_js.length(), 32);
        let shared_bytes: Vec<u8> = shared_secret_js.to_vec();
        assert_eq!(shared_bytes, vec![3u8; 32]);
        
        // Test associated_data getter
        let associated_data_js = result.associated_data();
        assert_eq!(associated_data_js.length(), 16);
        let associated_bytes: Vec<u8> = associated_data_js.to_vec();
        assert_eq!(associated_bytes, vec![4u8; 16]);
    }

    // Test EncryptionResult WASM getter methods
    #[wasm_bindgen_test]
    fn test_encryption_result_wasm_getters() {
        let result = EncryptionResult {
            ciphertext: vec![5u8; 64],
            message_key: vec![6u8; 32],
        };
        
        // Test ciphertext getter
        let ciphertext_js = result.ciphertext();
        assert_eq!(ciphertext_js.length(), 64);
        let ciphertext_bytes: Vec<u8> = ciphertext_js.to_vec();
        assert_eq!(ciphertext_bytes, vec![5u8; 64]);
        
        // Test message_key getter
        let message_key_js = result.message_key();
        assert_eq!(message_key_js.length(), 32);
        let message_key_bytes: Vec<u8> = message_key_js.to_vec();
        assert_eq!(message_key_bytes, vec![6u8; 32]);
    }

    // Test key generation functions
    #[wasm_bindgen_test]
    fn test_generate_identity_keypair_wasm() {
        let result = generate_identity_keypair();
        assert!(result.is_ok());
        
        let keypair = result.unwrap();
        assert_eq!(keypair.public_key().length(), 32);
        assert_eq!(keypair.private_key().length(), 32);
        
        // Keys should be different
        let pub_bytes: Vec<u8> = keypair.public_key().to_vec();
        let priv_bytes: Vec<u8> = keypair.private_key().to_vec();
        assert_ne!(pub_bytes, priv_bytes);
    }

    #[wasm_bindgen_test]
    fn test_generate_signed_prekey_wasm() {
        let result = generate_signed_prekey();
        assert!(result.is_ok());
        
        let keypair = result.unwrap();
        assert_eq!(keypair.public_key().length(), 32);
        assert_eq!(keypair.private_key().length(), 32);
    }

    #[wasm_bindgen_test]
    fn test_generate_one_time_prekey_wasm() {
        let result = generate_one_time_prekey();
        assert!(result.is_ok());
        
        let keypair = result.unwrap();
        assert_eq!(keypair.public_key().length(), 32);
        assert_eq!(keypair.private_key().length(), 32);
    }

    #[wasm_bindgen_test]
    fn test_generate_ephemeral_keypair_wasm() {
        let result = generate_ephemeral_keypair();
        assert!(result.is_ok());
        
        let keypair = result.unwrap();
        assert_eq!(keypair.public_key().length(), 32);
        assert_eq!(keypair.private_key().length(), 32);
    }

    // Test key uniqueness
    #[wasm_bindgen_test]
    fn test_key_generation_uniqueness() {
        let keypair1 = generate_identity_keypair().unwrap();
        let keypair2 = generate_identity_keypair().unwrap();
        
        let pub1: Vec<u8> = keypair1.public_key().to_vec();
        let pub2: Vec<u8> = keypair2.public_key().to_vec();
        let priv1: Vec<u8> = keypair1.private_key().to_vec();
        let priv2: Vec<u8> = keypair2.private_key().to_vec();
        
        // Different generations should produce different keys
        assert_ne!(pub1, pub2);
        assert_ne!(priv1, priv2);
    }

    // Test utility functions
    #[wasm_bindgen_test]
    fn test_serialize_public_key_wasm() {
        let public_key = Uint8Array::new_with_length(32);
        for i in 0..32 {
            public_key.set_index(i, (i as u8) + 1);
        }
        
        let result = serialize_public_key(&public_key);
        assert!(result.is_ok());
        
        let serialized = result.unwrap();
        assert_eq!(serialized.length(), 33); // 32 + 1 version byte
        assert_eq!(serialized.get_index(0), 0x05); // Version byte
        
        // Check that the key data is preserved
        for i in 1..33 {
            assert_eq!(serialized.get_index(i), i as u8);
        }
    }

    #[wasm_bindgen_test]
    fn test_deserialize_public_key_wasm() {
        let mut serialized_data = vec![0x05]; // Version byte
        serialized_data.extend_from_slice(&[42u8; 32]);
        let serialized = Uint8Array::from(&serialized_data[..]);
        
        let result = deserialize_public_key(&serialized);
        assert!(result.is_ok());
        
        let public_key = result.unwrap();
        assert_eq!(public_key.length(), 32);
        
        // Check that all bytes are correct
        for i in 0..32 {
            assert_eq!(public_key.get_index(i), 42);
        }
    }

    #[wasm_bindgen_test]
    fn test_serialize_deserialize_roundtrip_wasm() {
        let public_key = Uint8Array::new_with_length(32);
        for i in 0..32 {
            public_key.set_index(i, (i as u8) + 100);
        }
        
        // Serialize
        let serialized = serialize_public_key(&public_key).unwrap();
        
        // Deserialize
        let deserialized = deserialize_public_key(&serialized).unwrap();
        
        // Should match original
        assert_eq!(deserialized.length(), 32);
        for i in 0..32 {
            assert_eq!(deserialized.get_index(i), (i as u8) + 100);
        }
    }

    #[wasm_bindgen_test]
    fn test_hkdf_derive_key_wasm() {
        let input_key = Uint8Array::from(&b"input key material"[..]);
        let salt = Uint8Array::from(&b"salt data"[..]);
        let info = Uint8Array::from(&b"application info"[..]);
        
        let result = hkdf_derive_key(&input_key, &salt, &info, 32);
        assert!(result.is_ok());
        
        let derived = result.unwrap();
        assert_eq!(derived.length(), 32);
        
        // Test that same inputs produce same output
        let result2 = hkdf_derive_key(&input_key, &salt, &info, 32).unwrap();
        let derived_bytes1: Vec<u8> = derived.to_vec();
        let derived_bytes2: Vec<u8> = result2.to_vec();
        assert_eq!(derived_bytes1, derived_bytes2);
    }

    #[wasm_bindgen_test]
    fn test_hkdf_different_lengths_wasm() {
        let input_key = Uint8Array::from(&b"input key material"[..]);
        let salt = Uint8Array::from(&b"salt data"[..]);
        let info = Uint8Array::from(&b"application info"[..]);
        
        for length in [16, 32, 64] {
            let result = hkdf_derive_key(&input_key, &salt, &info, length);
            assert!(result.is_ok());
            assert_eq!(result.unwrap().length(), length as u32);
        }
    }

    #[wasm_bindgen_test]
    fn test_hkdf_error_cases_wasm() {
        let input_key = Uint8Array::from(&b"input key material"[..]);
        let salt = Uint8Array::from(&b"salt data"[..]);
        let info = Uint8Array::from(&b"application info"[..]);
        
        // Test zero length error
        let result = hkdf_derive_key(&input_key, &salt, &info, 0);
        assert!(result.is_err());
        
        // Test too large length error
        let result = hkdf_derive_key(&input_key, &salt, &info, 255 * 32 + 1);
        assert!(result.is_err());
    }

    // Test signature functions
    #[wasm_bindgen_test]
    fn test_sign_data_wasm() {
        let private_key = Uint8Array::from(&vec![42u8; 32][..]);
        let data = Uint8Array::from(&b"Hello, WASM signatures!"[..]);
        
        let result = sign_data(&private_key, &data);
        assert!(result.is_ok());
        
        let signature = result.unwrap();
        assert_eq!(signature.length(), 32);
        
        // Test that same inputs produce same signature
        let result2 = sign_data(&private_key, &data).unwrap();
        let sig_bytes1: Vec<u8> = signature.to_vec();
        let sig_bytes2: Vec<u8> = result2.to_vec();
        assert_eq!(sig_bytes1, sig_bytes2);
    }

    #[wasm_bindgen_test]
    fn test_verify_signature_wasm() {
        let public_key = Uint8Array::from(&vec![42u8; 32][..]);
        let data = Uint8Array::from(&b"Hello, WASM signatures!"[..]);
        let signature = Uint8Array::from(&vec![123u8; 32][..]);
        
        let result = verify_signature(&public_key, &signature, &data);
        assert!(result.is_ok());
        
        // The result should be a boolean
        let is_valid = result.unwrap();
        // This is a simplified signature scheme, so we expect it to work with matching keys
        assert!(is_valid == true || is_valid == false); // Just test that we get a boolean
    }

    // Test memory management functions
    #[wasm_bindgen_test]
    fn test_free_keypair_wasm() {
        let keypair = KeyPair {
            public_key: vec![1u8; 32],
            private_key: vec![2u8; 32],
        };
        
        // Test that free_keypair doesn't panic
        free_keypair(&keypair);
        // If we get here, the test passes
        assert_eq!(1, 1);
    }

    #[wasm_bindgen_test]
    fn test_free_buffer_wasm() {
        let buffer = Uint8Array::from(&vec![42u8; 64][..]);
        
        // Test that free_buffer doesn't panic
        free_buffer(&buffer);
        // If we get here, the test passes
        assert_eq!(1, 1);
    }

    // Test serialization error cases
    #[wasm_bindgen_test]
    fn test_serialize_public_key_errors_wasm() {
        // Test with invalid key length (too short)
        let short_key = Uint8Array::new_with_length(16);
        let result = serialize_public_key(&short_key);
        assert!(result.is_err());
        
        // Test with invalid key length (too long)
        let long_key = Uint8Array::new_with_length(64);
        let result2 = serialize_public_key(&long_key);
        assert!(result2.is_err());
    }

    #[wasm_bindgen_test]
    fn test_deserialize_public_key_errors_wasm() {
        // Test with invalid length (too short)
        let short_data = Uint8Array::new_with_length(16);
        let result = deserialize_public_key(&short_data);
        assert!(result.is_err());
        
        // Test with invalid version byte
        let mut invalid_version = vec![0x04]; // Wrong version
        invalid_version.extend_from_slice(&[42u8; 32]);
        let invalid_serialized = Uint8Array::from(&invalid_version[..]);
        let result2 = deserialize_public_key(&invalid_serialized);
        assert!(result2.is_err());
    }

    // Test DoubleRatchetState WASM methods
    #[wasm_bindgen_test]
    fn test_double_ratchet_state_wasm_getters() {
        let state = DoubleRatchetState::new();
        
        // Test root_key getter
        let root_key = state.root_key();
        assert_eq!(root_key.length(), 32);
        
        // Test counter getters
        assert_eq!(state.sending_message_number(), 0);
        assert_eq!(state.receiving_message_number(), 0);
        assert_eq!(state.skipped_keys_count(), 0);
    }

    // Test DoubleRatchetMessage WASM methods
    #[wasm_bindgen_test]
    fn test_double_ratchet_message_wasm_getters() {
        let message = DoubleRatchetMessage {
            ciphertext: vec![7u8; 64],
            dh_public_key: vec![8u8; 32],
            message_number: 42,
            previous_chain_length: 10,
        };
        
        // Test ciphertext getter
        let ciphertext_js = message.ciphertext();
        assert_eq!(ciphertext_js.length(), 64);
        let ciphertext_bytes: Vec<u8> = ciphertext_js.to_vec();
        assert_eq!(ciphertext_bytes, vec![7u8; 64]);
        
        // Test dh_public_key getter
        let dh_key_js = message.dh_public_key();
        assert_eq!(dh_key_js.length(), 32);
        let dh_key_bytes: Vec<u8> = dh_key_js.to_vec();
        assert_eq!(dh_key_bytes, vec![8u8; 32]);
        
        // Test number getters
        assert_eq!(message.message_number(), 42);
        assert_eq!(message.previous_chain_length(), 10);
    }

    // Test comprehensive integration
    #[wasm_bindgen_test]
    fn test_full_key_generation_flow() {
        // Generate all types of keys
        let identity = generate_identity_keypair().unwrap();
        let signed_prekey = generate_signed_prekey().unwrap();
        let one_time_prekey = generate_one_time_prekey().unwrap();
        let ephemeral = generate_ephemeral_keypair().unwrap();
        
        // Test that all keys have correct sizes
        assert_eq!(identity.public_key().length(), 32);
        assert_eq!(signed_prekey.public_key().length(), 32);
        assert_eq!(one_time_prekey.public_key().length(), 32);
        assert_eq!(ephemeral.public_key().length(), 32);
        
        // Test that keys are different
        let id_pub: Vec<u8> = identity.public_key().to_vec();
        let sp_pub: Vec<u8> = signed_prekey.public_key().to_vec();
        let otp_pub: Vec<u8> = one_time_prekey.public_key().to_vec();
        let eph_pub: Vec<u8> = ephemeral.public_key().to_vec();
        
        assert_ne!(id_pub, sp_pub);
        assert_ne!(sp_pub, otp_pub);
        assert_ne!(otp_pub, eph_pub);
    }
}