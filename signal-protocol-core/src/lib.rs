//! Signal Protocol Core - Pure Rust implementation for formal verification
//!
//! This crate contains the core protocol logic without WASM bindings.
//! It is designed for extraction to F* via hax for formal verification.

pub mod crypto;
pub mod double_ratchet;
pub mod error;
pub mod keys;
pub mod types;
pub mod x3dh;

pub use crypto::{
    ct_eq, hkdf_derive, hmac_sha256, sign_data_internal, simple_ecdh, validate_x25519_public_key,
    verify_signature_internal, KEY_LEN, SIGNATURE_LEN,
};
pub use double_ratchet::{
    cleanup_skipped_message_keys_internal, derive_message_key, derive_next_chain_key,
    double_ratchet_decrypt_internal, double_ratchet_encrypt_internal,
    initialize_double_ratchet_internal, perform_dh_ratchet_step, skip_message_keys,
    DoubleRatchetMessage, DoubleRatchetState, SkippedKey,
};
pub use error::SignalError;
pub use keys::{
    generate_dh_ratchet_keypair, generate_ephemeral_keypair, generate_identity_keypair,
    generate_one_time_prekey, generate_signed_prekey, generate_x25519_keypair_internal,
    generate_ed25519_keypair_internal,
};
pub use types::{EncryptionResult, IdentityKeyPair, KeyPair, X3DHResult};
pub use x3dh::{x3dh_initiate, x3dh_initiate_internal, x3dh_respond_internal, X3DH_F_PREFIX};
