/* tslint:disable */
/* eslint-disable */
/**
 * Generate an identity key pair for long-term user identification
 *
 * Identity keys are long-lived keys that identify a user or device.
 * They are used in the X3DH key exchange protocol and for signing
 * other keys to establish authenticity.
 *
 * ## Implementation
 * Uses X25519 (Curve25519 Diffie-Hellman) for key agreement operations.
 * This provides 128-bit security level with efficient constant-time operations.
 *
 * ## Security Properties
 * - Uses OS-level entropy source (OsRng)
 * - Generates proper Curve25519 scalar/point pair
 * - Public key is valid curve point derived via scalar multiplication
 * - Constant-time operations prevent timing attacks
 *
 * ## Usage
 * Each user/device should generate one identity key pair and use it
 * consistently across all communication sessions. The public key
 * can be distributed through a key server or other trusted mechanism.
 *
 * ## Returns
 * A `KeyPair` containing the identity public and private keys (32 bytes each)
 */
export function generate_identity_keypair(): KeyPair;
/**
 * Generate a signed prekey for medium-term use in key exchanges
 *
 * Signed prekeys are generated periodically (e.g., weekly) and signed
 * by the identity key to prove authenticity. They are used in the X3DH
 * protocol to establish initial communication.
 *
 * ## Implementation
 * Uses X25519 (Curve25519 Diffie-Hellman) for key agreement operations.
 *
 * ## Purpose
 * - Provides forward secrecy by rotating regularly
 * - Enables asynchronous key exchange when recipient is offline
 * - Signed by identity key for authenticity verification
 *
 * ## Security Properties
 * - Real elliptic curve cryptography (X25519)
 * - Constant-time operations
 * - Proper scalar/point derivation
 *
 * ## Returns
 * A `KeyPair` containing the signed prekey public and private keys (32 bytes each)
 */
export function generate_signed_prekey(): KeyPair;
/**
 * Generate a one-time prekey for single-use in key exchanges
 *
 * One-time prekeys provide additional forward secrecy by being used only once.
 * They are consumed during the X3DH key exchange and then discarded,
 * ensuring that compromise of long-term keys doesn't affect past communications.
 *
 * ## Implementation
 * Uses X25519 (Curve25519 Diffie-Hellman) for key agreement operations.
 *
 * ## Security Benefits
 * - Perfect forward secrecy (used only once)
 * - Prevents replay attacks on key exchanges
 * - Protects against compromise of identity/signed prekeys
 * - Real elliptic curve cryptography
 *
 * ## Returns
 * A `KeyPair` containing the one-time prekey public and private keys (32 bytes each)
 */
export function generate_one_time_prekey(): KeyPair;
/**
 * Generate an ephemeral key pair for temporary use in key exchanges
 *
 * Ephemeral keys are generated fresh for each key exchange session
 * and provide additional forward secrecy. They are never stored
 * long-term and are discarded after the key exchange completes.
 *
 * ## Implementation
 * Uses X25519 (Curve25519 Diffie-Hellman) for key agreement operations.
 *
 * ## Use Cases
 * - X3DH key exchange initiation
 * - Session-specific entropy
 * - Enhanced forward secrecy guarantees
 *
 * ## Security Properties
 * - Real elliptic curve cryptography (X25519)
 * - Constant-time operations
 * - Fresh randomness for each generation
 *
 * ## Returns
 * A `KeyPair` containing the ephemeral public and private keys (32 bytes each)
 */
export function generate_ephemeral_keypair(): KeyPair;
/**
 * Sign data using Ed25519 digital signature algorithm
 *
 * Creates a cryptographically secure digital signature that proves the data
 * was signed by the holder of the corresponding Ed25519 private key.
 * The signature can be verified by anyone who has the public key.
 *
 * ## Implementation
 * Uses Ed25519 (Edwards-curve Digital Signature Algorithm) which provides:
 * - 128-bit security level
 * - Deterministic signatures (same input = same signature)
 * - Small signature size (64 bytes)
 * - Fast verification
 *
 * ## Usage Example
 * ```javascript
 * const signature = sign_data(privateKey, message);
 * const isValid = verify_signature(publicKey, signature, message);
 * ```
 *
 * ## Parameters
 * - `private_key`: The signer's Ed25519 private key as Uint8Array (must be 32 bytes)
 * - `data`: The data to sign as Uint8Array
 *
 * ## Returns
 * A Uint8Array containing the 64-byte Ed25519 signature
 *
 * ## Errors
 * - Returns error if private key is not exactly 32 bytes
 * - Returns error if signing operation fails
 */
export function sign_data(private_key: Uint8Array, data: Uint8Array): Uint8Array;
/**
 * Verify an Ed25519 digital signature
 *
 * Verifies that a signature was created by the holder of the private key
 * corresponding to the given Ed25519 public key. This ensures message
 * authenticity and integrity through elliptic curve cryptography.
 *
 * ## Security Properties
 * - **Unforgeability**: Cannot create valid signatures without private key
 * - **Non-repudiation**: Signer cannot deny creating the signature
 * - **Integrity**: Any modification to data invalidates the signature
 * - **Constant-time**: Verification takes same time regardless of validity
 *
 * ## Usage Example
 * ```javascript
 * const isValid = verify_signature(publicKey, signature, originalMessage);
 * if (isValid) {
 *     console.log("Signature is valid!");
 * }
 * ```
 *
 * ## Parameters
 * - `public_key`: The signer's Ed25519 public key as Uint8Array (must be 32 bytes)
 * - `signature`: The Ed25519 signature to verify as Uint8Array (must be 64 bytes)
 * - `data`: The original signed data as Uint8Array
 *
 * ## Returns
 * `true` if the signature is valid, `false` otherwise
 *
 * ## Errors
 * - Returns error if public key is not exactly 32 bytes
 * - Returns error if signature is not exactly 64 bytes
 * - Returns error if key format is invalid
 */
export function verify_signature(public_key: Uint8Array, signature: Uint8Array, data: Uint8Array): boolean;
/**
 * Initiate X3DH key exchange (Alice's side)
 * 
 * This function performs the X3DH key agreement from the initiator's perspective.
 * Alice combines her keys with Bob's prekeys to compute a shared secret that
 * both parties can independently derive.
 * 
 * ## X3DH Protocol Overview
 * The X3DH protocol performs multiple Diffie-Hellman computations:
 * 1. DH1: Alice_Identity_Private × Bob_SignedPrekey_Public
 * 2. DH2: Alice_Ephemeral_Private × Bob_Identity_Public  
 * 3. DH3: Alice_Ephemeral_Private × Bob_SignedPrekey_Public
 * 4. DH4: Alice_Ephemeral_Private × Bob_OneTimePrekey_Public (optional)
 * 
 * The results are concatenated and fed into HKDF to derive the final shared secret.
 * 
 * ## Security Properties
 * - **Forward Secrecy**: Compromise of long-term keys doesn't affect past sessions
 * - **Authentication**: Both parties prove their identity through key ownership
 * - **Asynchronous**: Bob doesn't need to be online during key exchange
 * - **Deniability**: No long-term proof of participation in conversations
 * 
 * ## Parameters
 * - `alice_identity_private`: Alice's long-term identity private key (32 bytes)
 * - `alice_ephemeral_private`: Alice's session-specific ephemeral private key (32 bytes)
 * - `bob_identity_public`: Bob's identity public key (32 bytes)
 * - `bob_signed_prekey_public`: Bob's signed prekey public key (32 bytes)
 * - `bob_one_time_prekey_public`: Optional one-time prekey for additional forward secrecy
 * 
 * ## Returns
 * An `X3DHResult` containing the shared secret and associated data
 * 
 * ## Example Usage
 * ```rust
 * let result = x3dh_initiate(
 *     &alice_identity_private,
 *     &alice_ephemeral_private,
 *     &bob_identity_public,
 *     &bob_signed_prekey_public,
 *     Some(bob_one_time_prekey_public)
 * )?;
 * let shared_secret = result.shared_secret();
 * ```
 */
export function x3dh_initiate(alice_identity_private: Uint8Array, alice_ephemeral_private: Uint8Array, bob_identity_public: Uint8Array, bob_signed_prekey_public: Uint8Array, bob_one_time_prekey_public?: Uint8Array | null): X3DHResult;
/**
 * Respond to X3DH key exchange (Bob's side)
 * 
 * This function performs the X3DH key agreement from the responder's perspective.
 * Bob uses his prekeys and Alice's ephemeral key to compute the same shared secret
 * that Alice derived on her side.
 * 
 * ## Protocol Symmetry
 * Bob performs the exact same DH computations as Alice, but uses his private keys
 * instead of Alice's. The commutativity property of our simplified ECDH ensures
 * that both parties compute identical shared secrets.
 * 
 * ## Key Derivation Order
 * Bob must perform the DH computations in the same order as Alice:
 * 1. DH1: Bob_SignedPrekey_Private × Alice_Identity_Public (= Alice's DH1)
 * 2. DH2: Bob_Identity_Private × Alice_Ephemeral_Public (= Alice's DH2)
 * 3. DH3: Bob_SignedPrekey_Private × Alice_Ephemeral_Public (= Alice's DH3)
 * 4. DH4: Bob_OneTimePrekey_Private × Alice_Ephemeral_Public (= Alice's DH4, optional)
 * 
 * ## Parameters
 * - `bob_identity_private`: Bob's long-term identity private key (32 bytes)
 * - `bob_signed_prekey_private`: Bob's signed prekey private key (32 bytes)
 * - `bob_one_time_prekey_private`: Optional one-time prekey private key (32 bytes)
 * - `alice_identity_public`: Alice's identity public key (32 bytes)
 * - `alice_ephemeral_public`: Alice's ephemeral public key from the key exchange (32 bytes)
 * 
 * ## Returns
 * An `X3DHResult` containing the same shared secret Alice computed
 * 
 * ## Example Usage
 * ```rust
 * let result = x3dh_respond(
 *     &bob_identity_private,
 *     &bob_signed_prekey_private,
 *     Some(bob_one_time_prekey_private),
 *     &alice_identity_public,
 *     &alice_ephemeral_public
 * )?;
 * let shared_secret = result.shared_secret();
 * ```
 */
export function x3dh_respond(bob_identity_private: Uint8Array, bob_signed_prekey_private: Uint8Array, bob_one_time_prekey_private: Uint8Array | null | undefined, alice_identity_public: Uint8Array, alice_ephemeral_public: Uint8Array): X3DHResult;
/**
 * Encrypt a message using Signal Protocol message encryption
 * 
 * This function implements the Signal Protocol's message encryption scheme,
 * which provides forward secrecy by deriving a unique key for each message.
 * The encryption uses AES-GCM for authenticated encryption, ensuring both
 * confidentiality and integrity.
 * 
 * ## Forward Secrecy Implementation
 * Each message is encrypted with a unique key derived from:
 * - The shared secret from X3DH key exchange
 * - A message-specific counter/number
 * - Cryptographic salt and info strings
 * 
 * This ensures that compromise of one message key doesn't affect other messages.
 * 
 * ## Encryption Process
 * 1. Derive message-specific key using HKDF
 * 2. Generate random 96-bit nonce for AES-GCM
 * 3. Encrypt plaintext with derived key and nonce
 * 4. Prepend nonce to ciphertext for transmission
 * 
 * ## Security Properties
 * - **Confidentiality**: AES-256-GCM encryption
 * - **Integrity**: Built-in authentication tag
 * - **Forward Secrecy**: Unique key per message
 * - **Replay Protection**: Message numbering
 * 
 * ## Parameters
 * - `shared_secret`: The shared secret from X3DH key exchange (32 bytes)
 * - `plaintext`: The message to encrypt
 * - `message_number`: Sequential message counter for forward secrecy
 * 
 * ## Returns
 * An `EncryptionResult` containing:
 * - `ciphertext`: Nonce + encrypted data + auth tag
 * - `message_key`: The derived key for this specific message
 * 
 * ## Example Usage
 * ```javascript
 * const result = encrypt_message(sharedSecret, plaintext, messageNumber);
 * const encryptedData = result.ciphertext();
 * const messageKey = result.message_key();
 * ```
 */
export function encrypt_message(shared_secret: Uint8Array, plaintext: Uint8Array, message_number: number): EncryptionResult;
/**
 * Decrypt a message using Signal Protocol message decryption
 * 
 * This function decrypts messages that were encrypted using the Signal Protocol's
 * message encryption scheme. It uses the provided message key and extracts the
 * nonce from the ciphertext to perform AES-GCM decryption.
 * 
 * ## Decryption Process
 * 1. Extract 96-bit nonce from the beginning of ciphertext
 * 2. Use provided message key for AES-GCM decryption
 * 3. Verify authentication tag during decryption
 * 4. Return decrypted plaintext
 * 
 * ## Security Verification
 * - Authentication tag verification ensures message integrity
 * - Nonce uniqueness prevents replay attacks
 * - Key verification ensures authorized decryption
 * 
 * ## Parameters
 * - `shared_secret`: The original shared secret (for validation/logging)
 * - `ciphertext`: The encrypted message with prepended nonce
 * - `message_key`: The derived key for this specific message
 * - `message_number`: The message counter (for logging/validation)
 * 
 * ## Returns
 * A `Uint8Array` containing the decrypted plaintext message
 * 
 * ## Errors
 * - Returns error if ciphertext is too short (< 12 bytes for nonce)
 * - Returns error if AES-GCM decryption fails (wrong key, corrupted data, etc.)
 * - Returns error if authentication tag verification fails
 * 
 * ## Example Usage
 * ```javascript
 * const plaintext = decrypt_message(
 *     sharedSecret, 
 *     encryptedData, 
 *     messageKey, 
 *     messageNumber
 * );
 * const message = new TextDecoder().decode(plaintext);
 * ```
 */
export function decrypt_message(shared_secret: Uint8Array, ciphertext: Uint8Array, message_key: Uint8Array, message_number: number): Uint8Array;
/**
 * Serialize a public key for transmission or storage
 * 
 * This function prepares a public key for transmission over a network or
 * storage in a database by adding protocol metadata. In the Signal Protocol,
 * public keys are often serialized with version bytes to ensure compatibility
 * and proper parsing.
 * 
 * ## Serialization Format
 * - Version byte (0x05): Indicates compressed point format
 * - Key data: The raw 32-byte public key
 * - Total size: 33 bytes
 * 
 * ## Use Cases
 * - Transmitting public keys in key exchange messages
 * - Storing public keys in databases or key servers
 * - Including public keys in signed prekey bundles
 * - Protocol message headers
 * 
 * ## Parameters
 * - `public_key`: The 32-byte public key to serialize
 * 
 * ## Returns
 * A 33-byte serialized key with version prefix
 * 
 * ## Errors
 * - Returns error if public key is not exactly 32 bytes
 * 
 * ## Example Usage
 * ```javascript
 * const serialized = serialize_public_key(publicKey);
 * // Send serialized key over network or store in database
 * ```
 */
export function serialize_public_key(public_key: Uint8Array): Uint8Array;
/**
 * Deserialize a public key from its serialized format
 * 
 * This function extracts a public key from its serialized representation,
 * performing validation checks to ensure the data is well-formed and
 * compatible with the expected protocol version.
 * 
 * ## Deserialization Process
 * 1. Validate total length (must be 33 bytes)
 * 2. Check version byte (must be 0x05)
 * 3. Extract 32-byte key data
 * 4. Return raw key bytes
 * 
 * ## Security Considerations
 * - Validates data integrity before processing
 * - Rejects malformed or unexpected formats
 * - Prevents buffer overflow attacks
 * - Ensures protocol compatibility
 * 
 * ## Parameters
 * - `serialized_key`: The 33-byte serialized key with version prefix
 * 
 * ## Returns
 * The original 32-byte public key
 * 
 * ## Errors
 * - Returns error if serialized key is not 33 bytes
 * - Returns error if version byte is not 0x05
 * - Returns error for any malformed input
 * 
 * ## Example Usage
 * ```javascript
 * const publicKey = deserialize_public_key(receivedData);
 * // Use public key for cryptographic operations
 * ```
 */
export function deserialize_public_key(serialized_key: Uint8Array): Uint8Array;
/**
 * Derive cryptographic keys using HKDF (HMAC-based Key Derivation Function)
 * 
 * HKDF is the standard key derivation function used in the Signal Protocol
 * for expanding shared secrets into specific-purpose keys. It provides
 * cryptographic strength and domain separation for different key uses.
 * 
 * ## HKDF Algorithm
 * HKDF operates in two phases:
 * 1. **Extract**: Uses HMAC to extract pseudorandom key from input material
 * 2. **Expand**: Expands the pseudorandom key to desired output length
 * 
 * ## Security Properties
 * - **Entropy preservation**: Maintains entropy from input material
 * - **Domain separation**: Different info strings produce independent keys
 * - **Length flexibility**: Can produce keys of any required length
 * - **Cryptographic strength**: Based on proven HMAC construction
 * 
 * ## Use Cases
 * - Deriving message keys from shared secrets
 * - Creating separate encryption and authentication keys
 * - Key rotation and forward secrecy
 * - Protocol-specific key derivation
 * 
 * ## Parameters
 * - `input_key_material`: The source entropy (e.g., ECDH shared secret)
 * - `salt`: Optional salt for additional security (can be empty)
 * - `info`: Context-specific information for domain separation
 * - `output_length`: Desired length of derived key in bytes
 * 
 * ## Returns
 * A derived key of the specified length
 * 
 * ## Errors
 * - Returns error if HKDF expansion fails
 * - Returns error for invalid output lengths
 * 
 * ## Example Usage
 * ```javascript
 * const messageKey = hkdf_derive_key(
 *     sharedSecret,
 *     salt,
 *     new TextEncoder().encode("Signal_Message_Key"),
 *     32
 * );
 * ```
 */
export function hkdf_derive_key(input_key_material: Uint8Array, salt: Uint8Array, info: Uint8Array, output_length: number): Uint8Array;
/**
 * Free memory associated with a KeyPair (placeholder for manual memory management)
 * 
 * In Rust, memory management is automatic through RAII (Resource Acquisition Is Initialization).
 * This function exists for API compatibility with other implementations that might require
 * explicit memory management (e.g., C implementations).
 * 
 * ## Memory Management in Rust
 * - Rust automatically deallocates memory when variables go out of scope
 * - No manual memory management is typically required
 * - This function serves as a no-op placeholder for API compatibility
 * 
 * ## Use Cases
 * - API compatibility with C-based implementations
 * - Explicit documentation of cleanup points
 * - Future integration with custom allocators
 * - Testing memory management flows
 * 
 * ## Parameters
 * - `_keypair`: The KeyPair to "free" (parameter is ignored)
 * 
 * ## Example Usage
 * ```javascript
 * // Optional explicit cleanup (not required in Rust/WASM)
 * free_keypair(keyPair);
 * ```
 */
export function free_keypair(_keypair: KeyPair): void;
/**
 * Free memory associated with a buffer (placeholder for manual memory management)
 * 
 * Similar to `free_keypair`, this function exists for API compatibility.
 * Rust's automatic memory management handles buffer cleanup automatically
 * when the buffer goes out of scope.
 * 
 * ## Buffer Management
 * - Uint8Array data is automatically managed by the JavaScript engine
 * - Rust Vec<u8> data is automatically deallocated when dropped
 * - No manual intervention is required in typical usage
 * 
 * ## Parameters
 * - `_buffer`: The buffer to "free" (parameter is ignored)
 * 
 * ## Example Usage
 * ```javascript
 * // Optional explicit cleanup (not required in Rust/WASM)
 * free_buffer(buffer);
 * ```
 */
export function free_buffer(_buffer: Uint8Array): void;
export function initialize_double_ratchet(shared_secret: Uint8Array, is_initiator: boolean): DoubleRatchetState;
export function double_ratchet_encrypt(state: DoubleRatchetState, plaintext: Uint8Array): DoubleRatchetMessage;
export function double_ratchet_decrypt(state: DoubleRatchetState, message: DoubleRatchetMessage): Uint8Array;
export function cleanup_skipped_message_keys(state: DoubleRatchetState, max_keys: number): number;
/**
 * Initialize the WASM module
 * 
 * This function is automatically called when the WASM module is loaded.
 * It sets up error handling and logging for better debugging experience.
 */
export function main(): void;
export class DoubleRatchetMessage {
  private constructor();
  free(): void;
  readonly ciphertext: Uint8Array;
  readonly dh_public_key: Uint8Array;
  readonly message_number: number;
  readonly previous_chain_length: number;
}
export class DoubleRatchetState {
  free(): void;
  constructor();
  readonly root_key: Uint8Array;
  readonly sending_message_number: number;
  readonly receiving_message_number: number;
  readonly skipped_keys_count: number;
}
/**
 * Result of message encryption operation
 * 
 * Contains both the encrypted ciphertext and the derived message key.
 * The message key can be stored for future decryption operations,
 * enabling asynchronous message processing.
 * 
 * ## Forward Secrecy
 * Each message uses a unique derived key, ensuring that compromise
 * of one message key doesn't affect the security of other messages.
 */
export class EncryptionResult {
  private constructor();
  free(): void;
  /**
   * Get the ciphertext as a JavaScript Uint8Array
   * 
   * The ciphertext includes the nonce and authentication tag,
   * making it self-contained for transmission and storage.
   */
  readonly ciphertext: Uint8Array;
  /**
   * Get the message key as a JavaScript Uint8Array
   * 
   * This key is required for decryption and should be stored
   * securely alongside the ciphertext if needed for later access.
   */
  readonly message_key: Uint8Array;
}
/**
 * Cryptographic key pair structure
 * 
 * Represents a public/private key pair used in the Signal Protocol.
 * The keys are stored as byte vectors internally but exposed to JavaScript
 * as Uint8Array objects for compatibility.
 * 
 * ## Security Note
 * Private keys should be handled with extreme care and never exposed
 * in logs or transmitted over insecure channels.
 */
export class KeyPair {
  private constructor();
  free(): void;
  /**
   * Get the public key as a JavaScript Uint8Array
   * 
   * The public key can be safely shared with other parties for
   * encryption, signature verification, or key agreement protocols.
   */
  readonly public_key: Uint8Array;
  /**
   * Get the private key as a JavaScript Uint8Array
   * 
   * ⚠️ **WARNING**: Private keys must be handled securely.
   * Only access this when absolutely necessary for cryptographic operations.
   */
  readonly private_key: Uint8Array;
}
/**
 * Result of X3DH key exchange protocol
 * 
 * Contains the shared secret and associated data produced by the X3DH
 * key agreement protocol. This data is used to initialize secure
 * communication channels between two parties.
 * 
 * ## X3DH Protocol
 * The Extended Triple Diffie-Hellman (X3DH) is Signal's key agreement
 * protocol that provides mutual authentication and forward secrecy.
 */
export class X3DHResult {
  private constructor();
  free(): void;
  /**
   * Get the shared secret as a JavaScript Uint8Array
   * 
   * This secret should be used immediately for key derivation and
   * then securely wiped from memory when no longer needed.
   */
  readonly shared_secret: Uint8Array;
  /**
   * Get the associated data as a JavaScript Uint8Array
   * 
   * Associated data provides additional context for the key exchange
   * and can be used for protocol versioning or authentication.
   */
  readonly associated_data: Uint8Array;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_encryptionresult_free: (a: number, b: number) => void;
  readonly encryptionresult_ciphertext: (a: number) => any;
  readonly encryptionresult_message_key: (a: number) => any;
  readonly generate_identity_keypair: () => [number, number, number];
  readonly generate_signed_prekey: () => [number, number, number];
  readonly generate_one_time_prekey: () => [number, number, number];
  readonly generate_ephemeral_keypair: () => [number, number, number];
  readonly sign_data: (a: any, b: any) => [number, number, number];
  readonly verify_signature: (a: any, b: any, c: any) => [number, number, number];
  readonly x3dh_initiate: (a: any, b: any, c: any, d: any, e: number) => [number, number, number];
  readonly x3dh_respond: (a: any, b: any, c: number, d: any, e: any) => [number, number, number];
  readonly encrypt_message: (a: any, b: any, c: number) => [number, number, number];
  readonly decrypt_message: (a: any, b: any, c: any, d: number) => [number, number, number];
  readonly serialize_public_key: (a: any) => [number, number, number];
  readonly deserialize_public_key: (a: any) => [number, number, number];
  readonly hkdf_derive_key: (a: any, b: any, c: any, d: number) => [number, number, number];
  readonly free_keypair: (a: number) => void;
  readonly free_buffer: (a: any) => void;
  readonly __wbg_doubleratchetstate_free: (a: number, b: number) => void;
  readonly doubleratchetstate_new: () => number;
  readonly doubleratchetstate_root_key: (a: number) => any;
  readonly doubleratchetstate_sending_message_number: (a: number) => number;
  readonly doubleratchetstate_receiving_message_number: (a: number) => number;
  readonly doubleratchetstate_skipped_keys_count: (a: number) => number;
  readonly __wbg_doubleratchetmessage_free: (a: number, b: number) => void;
  readonly doubleratchetmessage_ciphertext: (a: number) => any;
  readonly doubleratchetmessage_dh_public_key: (a: number) => any;
  readonly doubleratchetmessage_message_number: (a: number) => number;
  readonly doubleratchetmessage_previous_chain_length: (a: number) => number;
  readonly initialize_double_ratchet: (a: any, b: number) => [number, number, number];
  readonly double_ratchet_encrypt: (a: number, b: any) => [number, number, number];
  readonly double_ratchet_decrypt: (a: number, b: number) => [number, number, number];
  readonly cleanup_skipped_message_keys: (a: number, b: number) => number;
  readonly main: () => void;
  readonly __wbg_x3dhresult_free: (a: number, b: number) => void;
  readonly __wbg_keypair_free: (a: number, b: number) => void;
  readonly x3dhresult_associated_data: (a: number) => any;
  readonly x3dhresult_shared_secret: (a: number) => any;
  readonly keypair_private_key: (a: number) => any;
  readonly keypair_public_key: (a: number) => any;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_export_2: WebAssembly.Table;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
