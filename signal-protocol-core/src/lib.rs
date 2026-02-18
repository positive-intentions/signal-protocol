//! Signal Protocol Core - Pure Rust implementation for formal verification
//!
//! This crate contains the core protocol logic without WASM bindings.
//! It is designed for extraction to F* via hax for formal verification.

pub mod error;
pub mod types;
pub mod crypto;
pub mod keys;
pub mod x3dh;
pub mod double_ratchet;

pub use error::SignalError;
pub use types::{KeyPair, X3DHResult, EncryptionResult};
pub use keys::{
    generate_identity_keypair,
    generate_signed_prekey,
    generate_one_time_prekey,
    generate_ephemeral_keypair,
};
pub use crypto::{sign_data_internal, verify_signature_internal, x25519_ecdh, simple_ecdh, validate_x25519_public_key};
pub use x3dh::{x3dh_initiate_internal, x3dh_respond_internal};
pub use double_ratchet::{
    derive_message_key,
    derive_next_chain_key,
    initialize_double_ratchet_internal,
    double_ratchet_encrypt_internal,
    double_ratchet_decrypt_internal,
    perform_dh_ratchet_step,
    skip_message_keys,
    cleanup_skipped_message_keys_internal,
    DoubleRatchetState,
    DoubleRatchetMessage,
};
