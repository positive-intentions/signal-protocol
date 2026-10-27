/* tslint:disable */
/* eslint-disable */
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
 * Initiator session: first chain DH against Bob's SPK (SP-2026-012).
 */
export function initialize_double_ratchet_initiator(shared_secret: Uint8Array, associated_data: Uint8Array, remote_spk_public: Uint8Array): DoubleRatchetState;
/**
 * Responder session: seed local SPK so Alice's first message matches (SP-2026-012).
 */
export function initialize_double_ratchet_responder(shared_secret: Uint8Array, associated_data: Uint8Array, local_spk_public: Uint8Array, local_spk_private: Uint8Array): DoubleRatchetState;
export function double_ratchet_encrypt(state: DoubleRatchetState, plaintext: Uint8Array): DoubleRatchetMessage;
export function double_ratchet_decrypt(state: DoubleRatchetState, message: DoubleRatchetMessage): Uint8Array;
export function cleanup_skipped_message_keys(state: DoubleRatchetState, max_keys: number): number;
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
 * Sign a signed-prekey public key with the identity private key (XEdDSA).
 */
export function sign_prekey(identity_private: Uint8Array, signed_prekey_public: Uint8Array): Uint8Array;
/**
 * Verify a signed-prekey signature with the identity public key (XEdDSA).
 */
export function verify_signed_prekey(identity_public: Uint8Array, signed_prekey_public: Uint8Array, signature: Uint8Array): void;
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
export function x3dh_initiate(alice_identity_private: Uint8Array, alice_ephemeral_private: Uint8Array, alice_identity_public: Uint8Array, bob_identity_public: Uint8Array, bob_signed_prekey_public: Uint8Array, bob_signed_prekey_signature: Uint8Array, bob_one_time_prekey_public?: Uint8Array | null): X3DHResult;
export function x3dh_respond(bob_identity_private: Uint8Array, bob_signed_prekey_private: Uint8Array, bob_one_time_prekey_private: Uint8Array | null | undefined, bob_identity_public: Uint8Array, alice_identity_public: Uint8Array, alice_ephemeral_public: Uint8Array): X3DHResult;
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
  readonly sign_data: (a: any, b: any) => [number, number, number];
  readonly verify_signature: (a: any, b: any, c: any) => [number, number, number];
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
  readonly initialize_double_ratchet_initiator: (a: any, b: any, c: any) => [number, number, number];
  readonly initialize_double_ratchet_responder: (a: any, b: any, c: any, d: any) => [number, number, number];
  readonly double_ratchet_encrypt: (a: number, b: any) => [number, number, number];
  readonly double_ratchet_decrypt: (a: number, b: number) => [number, number, number];
  readonly cleanup_skipped_message_keys: (a: number, b: number) => number;
  readonly generate_identity_keypair: () => [number, number, number];
  readonly generate_signed_prekey: () => [number, number, number];
  readonly generate_one_time_prekey: () => [number, number, number];
  readonly generate_ephemeral_keypair: () => [number, number, number];
  readonly sign_prekey: (a: any, b: any) => [number, number, number];
  readonly verify_signed_prekey: (a: any, b: any, c: any) => [number, number];
  readonly __wbg_keypair_free: (a: number, b: number) => void;
  readonly keypair_public_key: (a: number) => any;
  readonly keypair_private_key: (a: number) => any;
  readonly __wbg_encryptionresult_free: (a: number, b: number) => void;
  readonly encryptionresult_ciphertext: (a: number) => any;
  readonly serialize_public_key: (a: any) => [number, number, number];
  readonly deserialize_public_key: (a: any) => [number, number, number];
  readonly hkdf_derive_key: (a: any, b: any, c: any, d: number) => [number, number, number];
  readonly free_keypair: (a: number) => void;
  readonly free_buffer: (a: any) => void;
  readonly x3dh_initiate: (a: any, b: any, c: any, d: any, e: any, f: any, g: number) => [number, number, number];
  readonly x3dh_respond: (a: any, b: any, c: number, d: any, e: any, f: any) => [number, number, number];
  readonly main: () => void;
  readonly __wbg_x3dhresult_free: (a: number, b: number) => void;
  readonly x3dhresult_associated_data: (a: number) => any;
  readonly x3dhresult_shared_secret: (a: number) => any;
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
