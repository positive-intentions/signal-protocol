let wasm;

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_export_2.set(idx, obj);
    return idx;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

const cachedTextDecoder = (typeof TextDecoder !== 'undefined' ? new TextDecoder('utf-8', { ignoreBOM: true, fatal: true }) : { decode: () => { throw Error('TextDecoder not available') } } );

if (typeof TextDecoder !== 'undefined') { cachedTextDecoder.decode(); };

let cachedUint8ArrayMemory0 = null;

function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

let WASM_VECTOR_LEN = 0;

const cachedTextEncoder = (typeof TextEncoder !== 'undefined' ? new TextEncoder('utf-8') : { encode: () => { throw Error('TextEncoder not available') } } );

const encodeString = (typeof cachedTextEncoder.encodeInto === 'function'
    ? function (arg, view) {
    return cachedTextEncoder.encodeInto(arg, view);
}
    : function (arg, view) {
    const buf = cachedTextEncoder.encode(arg);
    view.set(buf);
    return {
        read: arg.length,
        written: buf.length
    };
});

function passStringToWasm0(arg, malloc, realloc) {

    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }

    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = encodeString(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

let cachedDataViewMemory0 = null;

function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function debugString(val) {
    // primitive types
    const type = typeof val;
    if (type == 'number' || type == 'boolean' || val == null) {
        return  `${val}`;
    }
    if (type == 'string') {
        return `"${val}"`;
    }
    if (type == 'symbol') {
        const description = val.description;
        if (description == null) {
            return 'Symbol';
        } else {
            return `Symbol(${description})`;
        }
    }
    if (type == 'function') {
        const name = val.name;
        if (typeof name == 'string' && name.length > 0) {
            return `Function(${name})`;
        } else {
            return 'Function';
        }
    }
    // objects
    if (Array.isArray(val)) {
        const length = val.length;
        let debug = '[';
        if (length > 0) {
            debug += debugString(val[0]);
        }
        for(let i = 1; i < length; i++) {
            debug += ', ' + debugString(val[i]);
        }
        debug += ']';
        return debug;
    }
    // Test for built-in
    const builtInMatches = /\[object ([^\]]+)\]/.exec(toString.call(val));
    let className;
    if (builtInMatches && builtInMatches.length > 1) {
        className = builtInMatches[1];
    } else {
        // Failed to match the standard '[object ClassName]'
        return toString.call(val);
    }
    if (className == 'Object') {
        // we're a user defined class or Object
        // JSON.stringify avoids problems with cycles, and is generally much
        // easier than looping through ownProperties of `val`.
        try {
            return 'Object(' + JSON.stringify(val) + ')';
        } catch (_) {
            return 'Object';
        }
    }
    // errors
    if (val instanceof Error) {
        return `${val.name}: ${val.message}\n${val.stack}`;
    }
    // TODO we could test for more things here, like `Set`s and `Map`s.
    return className;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_export_2.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}
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
 * @returns {KeyPair}
 */
export function generate_identity_keypair() {
    const ret = wasm.generate_identity_keypair();
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return KeyPair.__wrap(ret[0]);
}

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
 * @returns {KeyPair}
 */
export function generate_signed_prekey() {
    const ret = wasm.generate_signed_prekey();
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return KeyPair.__wrap(ret[0]);
}

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
 * @returns {KeyPair}
 */
export function generate_one_time_prekey() {
    const ret = wasm.generate_one_time_prekey();
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return KeyPair.__wrap(ret[0]);
}

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
 * @returns {KeyPair}
 */
export function generate_ephemeral_keypair() {
    const ret = wasm.generate_ephemeral_keypair();
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return KeyPair.__wrap(ret[0]);
}

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
 * @param {Uint8Array} private_key
 * @param {Uint8Array} data
 * @returns {Uint8Array}
 */
export function sign_data(private_key, data) {
    const ret = wasm.sign_data(private_key, data);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

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
 * @param {Uint8Array} public_key
 * @param {Uint8Array} signature
 * @param {Uint8Array} data
 * @returns {boolean}
 */
export function verify_signature(public_key, signature, data) {
    const ret = wasm.verify_signature(public_key, signature, data);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0] !== 0;
}

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
 * @param {Uint8Array} alice_identity_private
 * @param {Uint8Array} alice_ephemeral_private
 * @param {Uint8Array} bob_identity_public
 * @param {Uint8Array} bob_signed_prekey_public
 * @param {Uint8Array | null} [bob_one_time_prekey_public]
 * @returns {X3DHResult}
 */
export function x3dh_initiate(alice_identity_private, alice_ephemeral_private, bob_identity_public, bob_signed_prekey_public, bob_one_time_prekey_public) {
    const ret = wasm.x3dh_initiate(alice_identity_private, alice_ephemeral_private, bob_identity_public, bob_signed_prekey_public, isLikeNone(bob_one_time_prekey_public) ? 0 : addToExternrefTable0(bob_one_time_prekey_public));
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return X3DHResult.__wrap(ret[0]);
}

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
 * @param {Uint8Array} bob_identity_private
 * @param {Uint8Array} bob_signed_prekey_private
 * @param {Uint8Array | null | undefined} bob_one_time_prekey_private
 * @param {Uint8Array} alice_identity_public
 * @param {Uint8Array} alice_ephemeral_public
 * @returns {X3DHResult}
 */
export function x3dh_respond(bob_identity_private, bob_signed_prekey_private, bob_one_time_prekey_private, alice_identity_public, alice_ephemeral_public) {
    const ret = wasm.x3dh_respond(bob_identity_private, bob_signed_prekey_private, isLikeNone(bob_one_time_prekey_private) ? 0 : addToExternrefTable0(bob_one_time_prekey_private), alice_identity_public, alice_ephemeral_public);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return X3DHResult.__wrap(ret[0]);
}

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
 * @param {Uint8Array} shared_secret
 * @param {Uint8Array} plaintext
 * @param {number} message_number
 * @returns {EncryptionResult}
 */
export function encrypt_message(shared_secret, plaintext, message_number) {
    const ret = wasm.encrypt_message(shared_secret, plaintext, message_number);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return EncryptionResult.__wrap(ret[0]);
}

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
 * @param {Uint8Array} shared_secret
 * @param {Uint8Array} ciphertext
 * @param {Uint8Array} message_key
 * @param {number} message_number
 * @returns {Uint8Array}
 */
export function decrypt_message(shared_secret, ciphertext, message_key, message_number) {
    const ret = wasm.decrypt_message(shared_secret, ciphertext, message_key, message_number);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

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
 * @param {Uint8Array} public_key
 * @returns {Uint8Array}
 */
export function serialize_public_key(public_key) {
    const ret = wasm.serialize_public_key(public_key);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

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
 * @param {Uint8Array} serialized_key
 * @returns {Uint8Array}
 */
export function deserialize_public_key(serialized_key) {
    const ret = wasm.deserialize_public_key(serialized_key);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

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
 * @param {Uint8Array} input_key_material
 * @param {Uint8Array} salt
 * @param {Uint8Array} info
 * @param {number} output_length
 * @returns {Uint8Array}
 */
export function hkdf_derive_key(input_key_material, salt, info, output_length) {
    const ret = wasm.hkdf_derive_key(input_key_material, salt, info, output_length);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
}
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
 * @param {KeyPair} _keypair
 */
export function free_keypair(_keypair) {
    _assertClass(_keypair, KeyPair);
    wasm.free_keypair(_keypair.__wbg_ptr);
}

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
 * @param {Uint8Array} _buffer
 */
export function free_buffer(_buffer) {
    wasm.free_buffer(_buffer);
}

/**
 * Initialize a Double Ratchet state from a shared secret
 *
 * This function initializes the Double Ratchet state after an X3DH key exchange.
 * The shared secret from X3DH becomes the initial root key, and the first chain
 * keys are derived based on whether this party is the initiator or responder.
 *
 * ## Protocol Flow
 *
 * 1. **Initiator (Alice)**: Generates sending DH key pair immediately
 * 2. **Responder (Bob)**: Waits for first message to establish receiving chain
 * 3. Both parties derive their initial chain keys from the shared secret
 *
 * ## Parameters
 * - `shared_secret`: The shared secret from X3DH key exchange (32 bytes)
 * - `is_initiator`: Whether this party initiates the conversation
 *
 * ## Returns
 * An initialized `DoubleRatchetState` ready for message encryption/decryption
 *
 * ## Example Usage
 * ```rust
 * let shared_secret = x3dh_result.shared_secret();
 * let alice_state = initialize_double_ratchet(&shared_secret, true).unwrap();
 * let bob_state = initialize_double_ratchet(&shared_secret, false).unwrap();
 * ```
 * @param {Uint8Array} shared_secret
 * @param {boolean} is_initiator
 * @returns {DoubleRatchetState}
 */
export function initialize_double_ratchet(shared_secret, is_initiator) {
    const ret = wasm.initialize_double_ratchet(shared_secret, is_initiator);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return DoubleRatchetState.__wrap(ret[0]);
}

/**
 * Encrypt a message using the Double Ratchet
 *
 * This function encrypts a message using the current sending chain key,
 * derives a unique message key, and creates a message that includes all
 * information needed for decryption and ratchet state updates.
 *
 * ## Process
 * 1. Derive message key from current sending chain key
 * 2. Encrypt plaintext using AES-256-GCM with derived key
 * 3. Create authenticated data including DH public key and message number
 * 4. Advance sending chain key for next message
 * 5. Return encrypted message with metadata
 *
 * ## Parameters
 * - `state`: The Double Ratchet state (will be modified)
 * - `plaintext`: The message to encrypt
 *
 * ## Returns
 * A `DoubleRatchetMessage` containing encrypted data and metadata
 *
 * ## Errors
 * - Returns error if no sending chain key is available
 * - Returns error if encryption fails
 * - Returns error if chain key derivation fails
 * @param {DoubleRatchetState} state
 * @param {Uint8Array} plaintext
 * @returns {DoubleRatchetMessage}
 */
export function double_ratchet_encrypt(state, plaintext) {
    _assertClass(state, DoubleRatchetState);
    const ret = wasm.double_ratchet_encrypt(state.__wbg_ptr, plaintext);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return DoubleRatchetMessage.__wrap(ret[0]);
}

/**
 * Decrypt a message using the Double Ratchet
 *
 * This function decrypts a Double Ratchet message, handling DH ratchet steps
 * if needed and managing out-of-order message delivery through skipped message keys.
 *
 * ## Process
 * 1. Check for DH ratchet step (new DH public key)
 * 2. Handle skipped message keys for out-of-order delivery
 * 3. Derive or retrieve appropriate message key
 * 4. Decrypt message using AES-256-GCM
 * 5. Update ratchet state
 *
 * ## Parameters
 * - `state`: The Double Ratchet state (will be modified)
 * - `message`: The encrypted message to decrypt
 *
 * ## Returns
 * The decrypted plaintext as a Uint8Array
 *
 * ## Errors
 * - Returns error if DH ratchet step fails
 * - Returns error if message key derivation fails
 * - Returns error if decryption fails
 * - Returns error if authentication fails
 * @param {DoubleRatchetState} state
 * @param {DoubleRatchetMessage} message
 * @returns {Uint8Array}
 */
export function double_ratchet_decrypt(state, message) {
    _assertClass(state, DoubleRatchetState);
    _assertClass(message, DoubleRatchetMessage);
    const ret = wasm.double_ratchet_decrypt(state.__wbg_ptr, message.__wbg_ptr);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * Cleanup old skipped message keys
 *
 * This function removes old skipped message keys to prevent memory exhaustion.
 * It should be called periodically to maintain reasonable memory usage.
 *
 * ## Parameters
 * - `state`: The Double Ratchet state (will be modified)
 * - `max_keys`: Maximum number of skipped keys to keep
 *
 * ## Returns
 * Number of keys removed
 * @param {DoubleRatchetState} state
 * @param {number} max_keys
 * @returns {number}
 */
export function cleanup_skipped_message_keys(state, max_keys) {
    _assertClass(state, DoubleRatchetState);
    const ret = wasm.cleanup_skipped_message_keys(state.__wbg_ptr, max_keys);
    return ret >>> 0;
}

/**
 * Initialize the WASM module
 *
 * This function is automatically called when the WASM module is loaded.
 * It sets up error handling and logging for better debugging experience.
 */
export function main() {
    wasm.main();
}

const DoubleRatchetMessageFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_doubleratchetmessage_free(ptr >>> 0, 1));
/**
 * Result of Double Ratchet message encryption
 *
 * Contains the encrypted message along with the DH public key and message number
 * needed for the recipient to decrypt the message and update their ratchet state.
 */
export class DoubleRatchetMessage {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(DoubleRatchetMessage.prototype);
        obj.__wbg_ptr = ptr;
        DoubleRatchetMessageFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        DoubleRatchetMessageFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_doubleratchetmessage_free(ptr, 0);
    }
    /**
     * Get the ciphertext as a JavaScript Uint8Array
     * @returns {Uint8Array}
     */
    get ciphertext() {
        const ret = wasm.doubleratchetmessage_ciphertext(this.__wbg_ptr);
        return ret;
    }
    /**
     * Get the DH public key as a JavaScript Uint8Array
     * @returns {Uint8Array}
     */
    get dh_public_key() {
        const ret = wasm.doubleratchetmessage_dh_public_key(this.__wbg_ptr);
        return ret;
    }
    /**
     * Get the message number
     * @returns {number}
     */
    get message_number() {
        const ret = wasm.doubleratchetmessage_message_number(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Get the previous chain length
     * @returns {number}
     */
    get previous_chain_length() {
        const ret = wasm.doubleratchetmessage_previous_chain_length(this.__wbg_ptr);
        return ret >>> 0;
    }
}

const DoubleRatchetStateFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_doubleratchetstate_free(ptr >>> 0, 1));
/**
 * Double Ratchet state for one participant
 *
 * This structure maintains all the cryptographic state needed for the Double Ratchet
 * algorithm. It includes root keys, chain keys, message numbers, and skipped message
 * keys for out-of-order message handling.
 *
 * ## State Components
 *
 * - **Root Key**: Used to derive new chain keys during DH ratchet steps
 * - **Chain Keys**: Used to derive message keys and advance the symmetric ratchet
 * - **DH Key Pairs**: Used for Diffie-Hellman ratchet steps
 * - **Message Numbers**: Track the current position in each chain
 * - **Skipped Keys**: Store keys for messages that haven't arrived yet
 */
export class DoubleRatchetState {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(DoubleRatchetState.prototype);
        obj.__wbg_ptr = ptr;
        DoubleRatchetStateFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        DoubleRatchetStateFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_doubleratchetstate_free(ptr, 0);
    }
    /**
     * Create a new empty Double Ratchet state
     */
    constructor() {
        const ret = wasm.doubleratchetstate_new();
        this.__wbg_ptr = ret >>> 0;
        DoubleRatchetStateFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * Get the current root key
     * @returns {Uint8Array}
     */
    get root_key() {
        const ret = wasm.doubleratchetstate_root_key(this.__wbg_ptr);
        return ret;
    }
    /**
     * Get the sending message number
     * @returns {number}
     */
    get sending_message_number() {
        const ret = wasm.doubleratchetstate_sending_message_number(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Get the receiving message number
     * @returns {number}
     */
    get receiving_message_number() {
        const ret = wasm.doubleratchetstate_receiving_message_number(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Get the number of skipped message keys stored
     * @returns {number}
     */
    get skipped_keys_count() {
        const ret = wasm.doubleratchetstate_skipped_keys_count(this.__wbg_ptr);
        return ret >>> 0;
    }
}

const EncryptionResultFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_encryptionresult_free(ptr >>> 0, 1));
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

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(EncryptionResult.prototype);
        obj.__wbg_ptr = ptr;
        EncryptionResultFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        EncryptionResultFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_encryptionresult_free(ptr, 0);
    }
    /**
     * Get the ciphertext as a JavaScript Uint8Array
     *
     * The ciphertext includes the nonce and authentication tag,
     * making it self-contained for transmission and storage.
     * @returns {Uint8Array}
     */
    get ciphertext() {
        const ret = wasm.encryptionresult_ciphertext(this.__wbg_ptr);
        return ret;
    }
    /**
     * Get the message key as a JavaScript Uint8Array
     *
     * This key is required for decryption and should be stored
     * securely alongside the ciphertext if needed for later access.
     * @returns {Uint8Array}
     */
    get message_key() {
        const ret = wasm.encryptionresult_message_key(this.__wbg_ptr);
        return ret;
    }
}

const KeyPairFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_keypair_free(ptr >>> 0, 1));
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

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(KeyPair.prototype);
        obj.__wbg_ptr = ptr;
        KeyPairFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        KeyPairFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_keypair_free(ptr, 0);
    }
    /**
     * Get the public key as a JavaScript Uint8Array
     *
     * The public key can be safely shared with other parties for
     * encryption, signature verification, or key agreement protocols.
     * @returns {Uint8Array}
     */
    get public_key() {
        const ret = wasm.keypair_public_key(this.__wbg_ptr);
        return ret;
    }
    /**
     * Get the private key as a JavaScript Uint8Array
     *
     * ⚠️ **WARNING**: Private keys must be handled securely.
     * Only access this when absolutely necessary for cryptographic operations.
     * @returns {Uint8Array}
     */
    get private_key() {
        const ret = wasm.keypair_private_key(this.__wbg_ptr);
        return ret;
    }
}

const X3DHResultFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_x3dhresult_free(ptr >>> 0, 1));
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

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(X3DHResult.prototype);
        obj.__wbg_ptr = ptr;
        X3DHResultFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        X3DHResultFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_x3dhresult_free(ptr, 0);
    }
    /**
     * Get the shared secret as a JavaScript Uint8Array
     *
     * This secret should be used immediately for key derivation and
     * then securely wiped from memory when no longer needed.
     * @returns {Uint8Array}
     */
    get shared_secret() {
        const ret = wasm.x3dhresult_shared_secret(this.__wbg_ptr);
        return ret;
    }
    /**
     * Get the associated data as a JavaScript Uint8Array
     *
     * Associated data provides additional context for the key exchange
     * and can be used for protocol versioning or authentication.
     * @returns {Uint8Array}
     */
    get associated_data() {
        const ret = wasm.x3dhresult_associated_data(this.__wbg_ptr);
        return ret;
    }
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);

            } catch (e) {
                if (module.headers.get('Content-Type') != 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else {
                    throw e;
                }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);

    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };

        } else {
            return instance;
        }
    }
}

function __wbg_get_imports() {
    const imports = {};
    imports.wbg = {};
    imports.wbg.__wbg_buffer_609cc3eee51ed158 = function(arg0) {
        const ret = arg0.buffer;
        return ret;
    };
    imports.wbg.__wbg_call_672a4d21634d4a24 = function() { return handleError(function (arg0, arg1) {
        const ret = arg0.call(arg1);
        return ret;
    }, arguments) };
    imports.wbg.__wbg_call_7cccdd69e0791ae2 = function() { return handleError(function (arg0, arg1, arg2) {
        const ret = arg0.call(arg1, arg2);
        return ret;
    }, arguments) };
    imports.wbg.__wbg_crypto_574e78ad8b13b65f = function(arg0) {
        const ret = arg0.crypto;
        return ret;
    };
    imports.wbg.__wbg_error_7534b8e9a36f1ab4 = function(arg0, arg1) {
        let deferred0_0;
        let deferred0_1;
        try {
            deferred0_0 = arg0;
            deferred0_1 = arg1;
            console.error(getStringFromWasm0(arg0, arg1));
        } finally {
            wasm.__wbindgen_free(deferred0_0, deferred0_1, 1);
        }
    };
    imports.wbg.__wbg_getRandomValues_b8f5dbd5f3995a9e = function() { return handleError(function (arg0, arg1) {
        arg0.getRandomValues(arg1);
    }, arguments) };
    imports.wbg.__wbg_length_a446193dc22c12f8 = function(arg0) {
        const ret = arg0.length;
        return ret;
    };
    imports.wbg.__wbg_log_c222819a41e063d3 = function(arg0) {
        console.log(arg0);
    };
    imports.wbg.__wbg_msCrypto_a61aeb35a24c1329 = function(arg0) {
        const ret = arg0.msCrypto;
        return ret;
    };
    imports.wbg.__wbg_new_8a6f238a6ece86ea = function() {
        const ret = new Error();
        return ret;
    };
    imports.wbg.__wbg_new_a12002a7f91c75be = function(arg0) {
        const ret = new Uint8Array(arg0);
        return ret;
    };
    imports.wbg.__wbg_newnoargs_105ed471475aaf50 = function(arg0, arg1) {
        const ret = new Function(getStringFromWasm0(arg0, arg1));
        return ret;
    };
    imports.wbg.__wbg_newwithbyteoffsetandlength_d97e637ebe145a9a = function(arg0, arg1, arg2) {
        const ret = new Uint8Array(arg0, arg1 >>> 0, arg2 >>> 0);
        return ret;
    };
    imports.wbg.__wbg_newwithlength_a381634e90c276d4 = function(arg0) {
        const ret = new Uint8Array(arg0 >>> 0);
        return ret;
    };
    imports.wbg.__wbg_node_905d3e251edff8a2 = function(arg0) {
        const ret = arg0.node;
        return ret;
    };
    imports.wbg.__wbg_process_dc0fbacc7c1c06f7 = function(arg0) {
        const ret = arg0.process;
        return ret;
    };
    imports.wbg.__wbg_randomFillSync_ac0988aba3254290 = function() { return handleError(function (arg0, arg1) {
        arg0.randomFillSync(arg1);
    }, arguments) };
    imports.wbg.__wbg_require_60cc747a6bc5215a = function() { return handleError(function () {
        const ret = module.require;
        return ret;
    }, arguments) };
    imports.wbg.__wbg_set_65595bdd868b3009 = function(arg0, arg1, arg2) {
        arg0.set(arg1, arg2 >>> 0);
    };
    imports.wbg.__wbg_stack_0ed75d68575b0f3c = function(arg0, arg1) {
        const ret = arg1.stack;
        const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
        getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
    };
    imports.wbg.__wbg_static_accessor_GLOBAL_88a902d13a557d07 = function() {
        const ret = typeof global === 'undefined' ? null : global;
        return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
    };
    imports.wbg.__wbg_static_accessor_GLOBAL_THIS_56578be7e9f832b0 = function() {
        const ret = typeof globalThis === 'undefined' ? null : globalThis;
        return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
    };
    imports.wbg.__wbg_static_accessor_SELF_37c5d418e4bf5819 = function() {
        const ret = typeof self === 'undefined' ? null : self;
        return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
    };
    imports.wbg.__wbg_static_accessor_WINDOW_5de37043a91a9c40 = function() {
        const ret = typeof window === 'undefined' ? null : window;
        return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
    };
    imports.wbg.__wbg_subarray_aa9065fa9dc5df96 = function(arg0, arg1, arg2) {
        const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
        return ret;
    };
    imports.wbg.__wbg_versions_c01dfd4722a88165 = function(arg0) {
        const ret = arg0.versions;
        return ret;
    };
    imports.wbg.__wbindgen_debug_string = function(arg0, arg1) {
        const ret = debugString(arg1);
        const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
        getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
    };
    imports.wbg.__wbindgen_init_externref_table = function() {
        const table = wasm.__wbindgen_export_2;
        const offset = table.grow(4);
        table.set(0, undefined);
        table.set(offset + 0, undefined);
        table.set(offset + 1, null);
        table.set(offset + 2, true);
        table.set(offset + 3, false);
        ;
    };
    imports.wbg.__wbindgen_is_function = function(arg0) {
        const ret = typeof(arg0) === 'function';
        return ret;
    };
    imports.wbg.__wbindgen_is_object = function(arg0) {
        const val = arg0;
        const ret = typeof(val) === 'object' && val !== null;
        return ret;
    };
    imports.wbg.__wbindgen_is_string = function(arg0) {
        const ret = typeof(arg0) === 'string';
        return ret;
    };
    imports.wbg.__wbindgen_is_undefined = function(arg0) {
        const ret = arg0 === undefined;
        return ret;
    };
    imports.wbg.__wbindgen_memory = function() {
        const ret = wasm.memory;
        return ret;
    };
    imports.wbg.__wbindgen_string_new = function(arg0, arg1) {
        const ret = getStringFromWasm0(arg0, arg1);
        return ret;
    };
    imports.wbg.__wbindgen_throw = function(arg0, arg1) {
        throw new Error(getStringFromWasm0(arg0, arg1));
    };

    return imports;
}

function __wbg_init_memory(imports, memory) {

}

function __wbg_finalize_init(instance, module) {
    wasm = instance.exports;
    __wbg_init.__wbindgen_wasm_module = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;


    wasm.__wbindgen_start();
    return wasm;
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (typeof module !== 'undefined') {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();

    __wbg_init_memory(imports);

    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }

    const instance = new WebAssembly.Instance(module, imports);

    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (typeof module_or_path !== 'undefined') {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (typeof module_or_path === 'undefined') {
        module_or_path = new URL('signal_protocol_wasm_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    __wbg_init_memory(imports);

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync };
export default __wbg_init;
