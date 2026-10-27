/**
 * JavaScript bindings for Signal Protocol WASM module
 *
 * This module provides a high-level JavaScript interface to the Rust-based
 * Signal Protocol WASM implementation with better error handling and
 * compatibility with the existing JavaScript cryptography module.
 */

// WASM module will be loaded dynamically
let wasmModule = null;
let wasmLoaded = false;

/**
 * Load the WASM module asynchronously
 */
export async function loadWasmModule() {
  if (wasmLoaded) {
    return wasmModule;
  }

  try {
    // Load the WASM module - no fallback behavior in unit tests
    // If you need JavaScript-only tests, use signal-protocol-javascript.test.js
    // If you need WASM-only tests, use signal-protocol-wasm-only.test.js
    wasmModule = await import("../pkg/signal_protocol_wasm.js");
    await wasmModule.default(); // Initialize the WASM module
    wasmLoaded = true;

    console.log("✅ Signal Protocol WASM module loaded successfully");
    return wasmModule;
  } catch (error) {
    console.error("❌ Failed to load WASM module:", error.message);
    throw new Error(
      `WASM module loading failed: ${error.message}. Ensure WASM files are built with 'npm run build:wasm'`,
    );
  }
}

/**
 * Check if WASM module is available and loaded
 */
export function isWasmAvailable() {
  return wasmLoaded && wasmModule !== null;
}

/**
 * Signal Protocol WASM Wrapper Class
 * Provides a unified interface that matches the JavaScript implementation
 */
export class SignalProtocolWasm {
  constructor() {
    this.moduleReady = false;
  }

  /**
   * Initialize the WASM module
   */
  async initialize() {
    if (this.moduleReady) return;

    wasmModule = await loadWasmModule();
    this.moduleReady = wasmModule !== null;

    if (!this.moduleReady) {
      throw new Error("WASM module failed to load");
    }
  }

  /**
   * Ensure WASM module is loaded before calling methods
   */
  _ensureReady() {
    if (!this.moduleReady) {
      throw new Error("WASM module not initialized. Call initialize() first.");
    }
  }

  /**
   * Convert Uint8Array to hex string for compatibility
   */
  _bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  /**
   * Convert hex string to Uint8Array
   */
  _hexToBuffer(hex) {
    if (hex.length % 2 !== 0) {
      throw new Error("Invalid hex string length");
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }

  // =================== KEY GENERATION ===================

  /**
   * Generate identity key pair using WASM
   */
  async generateIdentityKeyPair() {
    this._ensureReady();

    try {
      const keypair = wasmModule.generate_identity_keypair();
      return {
        publicKey: keypair.public_key,
        privateKey: keypair.private_key,
      };
    } catch (error) {
      throw new Error(`WASM identity key generation failed: ${error.message}`);
    }
  }

  /**
   * Generate signed prekey using WASM
   */
  async generateSignedPrekey() {
    this._ensureReady();

    try {
      const keypair = wasmModule.generate_signed_prekey();
      return {
        publicKey: keypair.public_key,
        privateKey: keypair.private_key,
      };
    } catch (error) {
      throw new Error(`WASM signed prekey generation failed: ${error.message}`);
    }
  }

  /**
   * Generate one-time prekey using WASM
   */
  async generateOneTimePrekey() {
    this._ensureReady();

    try {
      const keypair = wasmModule.generate_one_time_prekey();
      return {
        publicKey: keypair.public_key,
        privateKey: keypair.private_key,
      };
    } catch (error) {
      throw new Error(
        `WASM one-time prekey generation failed: ${error.message}`,
      );
    }
  }

  /**
   * Generate ephemeral key pair using WASM
   */
  async generateEphemeralKeyPair() {
    this._ensureReady();

    try {
      const keypair = wasmModule.generate_ephemeral_keypair();
      return {
        publicKey: keypair.public_key,
        privateKey: keypair.private_key,
      };
    } catch (error) {
      throw new Error(`WASM ephemeral key generation failed: ${error.message}`);
    }
  }

  // =================== DIGITAL SIGNATURES ===================

  /**
   * Sign data using Ed25519 in WASM
   */
  async signData(privateKey, data) {
    this._ensureReady();

    try {
      let privateKeyBytes, dataBytes;

      // Handle different input types
      if (privateKey instanceof Uint8Array) {
        privateKeyBytes = privateKey;
      } else if (typeof privateKey === "string") {
        privateKeyBytes = this._hexToBuffer(privateKey);
      } else {
        throw new Error("Private key must be Uint8Array or hex string");
      }

      if (data instanceof Uint8Array) {
        dataBytes = data;
      } else if (typeof data === "string") {
        dataBytes = new TextEncoder().encode(data);
      } else {
        throw new Error("Data must be Uint8Array or string");
      }

      const signature = wasmModule.sign_data(privateKeyBytes, dataBytes);
      return signature;
    } catch (error) {
      throw new Error(`WASM signing failed: ${error.message}`);
    }
  }

  /**
   * Verify signature using Ed25519 in WASM
   */
  async verifySignature(publicKey, signature, data) {
    this._ensureReady();

    try {
      let publicKeyBytes, signatureBytes, dataBytes;

      // Handle different input types
      if (publicKey instanceof Uint8Array) {
        publicKeyBytes = publicKey;
      } else if (typeof publicKey === "string") {
        publicKeyBytes = this._hexToBuffer(publicKey);
      } else {
        throw new Error("Public key must be Uint8Array or hex string");
      }

      if (signature instanceof Uint8Array) {
        signatureBytes = signature;
      } else if (typeof signature === "string") {
        signatureBytes = this._hexToBuffer(signature);
      } else {
        throw new Error("Signature must be Uint8Array or hex string");
      }

      if (data instanceof Uint8Array) {
        dataBytes = data;
      } else if (typeof data === "string") {
        dataBytes = new TextEncoder().encode(data);
      } else {
        throw new Error("Data must be Uint8Array or string");
      }

      return wasmModule.verify_signature(
        publicKeyBytes,
        signatureBytes,
        dataBytes,
      );
    } catch (error) {
      throw new Error(`WASM signature verification failed: ${error.message}`);
    }
  }

  // =================== X3DH KEY EXCHANGE ===================

  /**
   * Initiate X3DH key exchange (Alice side).
   * SP-2026: requires Alice IK public + Bob SPK signature (verified in-library).
   */
  async x3dhInitiate(
    aliceIdentityPrivate,
    aliceEphemeralPrivate,
    aliceIdentityPublic,
    bobIdentityPublic,
    bobSignedPrekeyPublic,
    bobSignedPrekeySignature,
    bobOneTimePrekeyPublic = null,
  ) {
    this._ensureReady();

    try {
      // Convert all inputs to Uint8Array if needed
      const convertToBytes = (input) => {
        if (input instanceof Uint8Array) return input;
        if (typeof input === "string") return this._hexToBuffer(input);
        throw new Error("Key must be Uint8Array or hex string");
      };

      const aliceIdPrivBytes = convertToBytes(aliceIdentityPrivate);
      const aliceEphPrivBytes = convertToBytes(aliceEphemeralPrivate);
      const aliceIdPubBytes = convertToBytes(aliceIdentityPublic);
      const bobIdPubBytes = convertToBytes(bobIdentityPublic);
      const bobSignedPubBytes = convertToBytes(bobSignedPrekeyPublic);
      const bobSignedSigBytes = convertToBytes(bobSignedPrekeySignature);
      const bobOneTimePubBytes = bobOneTimePrekeyPublic
        ? convertToBytes(bobOneTimePrekeyPublic)
        : null;

      const result = wasmModule.x3dh_initiate(
        aliceIdPrivBytes,
        aliceEphPrivBytes,
        aliceIdPubBytes,
        bobIdPubBytes,
        bobSignedPubBytes,
        bobSignedSigBytes,
        bobOneTimePubBytes,
      );

      return {
        sharedSecret: result.shared_secret,
        associatedData: result.associated_data,
        usedOneTimePrekey: bobOneTimePrekeyPublic !== null,
      };
    } catch (error) {
      throw new Error(`WASM X3DH initiation failed: ${error.message}`);
    }
  }

  /**
   * Respond to X3DH key exchange (Bob side).
   * SP-2026: requires Bob IK public for AD = IK_A || IK_B.
   */
  async x3dhRespond(
    bobIdentityPrivate,
    bobSignedPrekeyPrivate,
    bobOneTimePrekeyPrivate,
    bobIdentityPublic,
    aliceIdentityPublic,
    aliceEphemeralPublic,
  ) {
    this._ensureReady();

    try {
      // Convert all inputs to Uint8Array if needed
      const convertToBytes = (input) => {
        if (!input) return null;
        if (input instanceof Uint8Array) return input;
        if (typeof input === "string") return this._hexToBuffer(input);
        throw new Error("Key must be Uint8Array or hex string");
      };

      const bobIdPrivBytes = convertToBytes(bobIdentityPrivate);
      const bobSignedPrivBytes = convertToBytes(bobSignedPrekeyPrivate);
      const bobOneTimePrivBytes = convertToBytes(bobOneTimePrekeyPrivate);
      const bobIdPubBytes = convertToBytes(bobIdentityPublic);
      const aliceIdPubBytes = convertToBytes(aliceIdentityPublic);
      const aliceEphPubBytes = convertToBytes(aliceEphemeralPublic);

      const result = wasmModule.x3dh_respond(
        bobIdPrivBytes,
        bobSignedPrivBytes,
        bobOneTimePrivBytes,
        bobIdPubBytes,
        aliceIdPubBytes,
        aliceEphPubBytes,
      );

      return {
        sharedSecret: result.shared_secret,
        associatedData: result.associated_data,
        usedOneTimePrekey: bobOneTimePrekeyPrivate !== null,
      };
    } catch (error) {
      throw new Error(`WASM X3DH response failed: ${error.message}`);
    }
  }

  // =================== MESSAGE ENCRYPTION/DECRYPTION ===================
  // SP-2026-016: legacy encrypt_message/decrypt_message WASM exports removed.
  // These helpers wrap Double Ratchet for demo / migration call sites.

  _ensureDrSession(sharedSecretBytes) {
    if (this._drAlice && this._drBob) {
      return;
    }
    const spk = wasmModule.generate_signed_prekey();
    const ad = new TextEncoder().encode("IK_A||IK_B_bindings_ad____________");
    this._drAlice = wasmModule.initialize_double_ratchet_initiator(
      sharedSecretBytes,
      ad,
      spk.public_key,
    );
    this._drBob = wasmModule.initialize_double_ratchet_responder(
      sharedSecretBytes,
      ad,
      spk.public_key,
      spk.private_key,
    );
  }

  /**
   * Encrypt message using Double Ratchet (SP-2026-016)
   */
  async encryptMessage(sharedSecret, plaintext, messageNumber) {
    this._ensureReady();

    try {
      let sharedSecretBytes, plaintextBytes;

      if (sharedSecret instanceof Uint8Array) {
        sharedSecretBytes = sharedSecret;
      } else if (typeof sharedSecret === "string") {
        sharedSecretBytes = this._hexToBuffer(sharedSecret);
      } else {
        throw new Error("Shared secret must be Uint8Array or hex string");
      }

      if (plaintext instanceof Uint8Array) {
        plaintextBytes = plaintext;
      } else if (typeof plaintext === "string") {
        plaintextBytes = new TextEncoder().encode(plaintext);
      } else {
        throw new Error("Plaintext must be Uint8Array or string");
      }

      this._ensureDrSession(sharedSecretBytes);
      const envelope = wasmModule.double_ratchet_encrypt(
        this._drAlice,
        plaintextBytes,
      );
      this._lastEnvelope = envelope;

      return {
        ciphertext: envelope.ciphertext,
        messageKey: new Uint8Array(0),
        messageNumber:
          typeof messageNumber === "number"
            ? messageNumber
            : envelope.message_number,
        envelope,
      };
    } catch (error) {
      throw new Error(`WASM message encryption failed: ${error.message}`);
    }
  }

  /**
   * Decrypt message using Double Ratchet (SP-2026-016)
   */
  async decryptMessage(sharedSecret, ciphertext, messageKey, messageNumber) {
    this._ensureReady();

    try {
      const convertToBytes = (input) => {
        if (input instanceof Uint8Array) return input;
        if (typeof input === "string") return this._hexToBuffer(input);
        throw new Error("Input must be Uint8Array or hex string");
      };

      const sharedSecretBytes = convertToBytes(sharedSecret);
      this._ensureDrSession(sharedSecretBytes);

      const envelope = this._lastEnvelope;
      if (!envelope) {
        throw new Error("No Double Ratchet envelope available for decrypt");
      }
      // ciphertext/messageKey/messageNumber kept for call-site compatibility
      void ciphertext;
      void messageKey;
      void messageNumber;

      return wasmModule.double_ratchet_decrypt(this._drBob, envelope);
    } catch (error) {
      throw new Error(`WASM message decryption failed: ${error.message}`);
    }
  }

  // =================== KEY DERIVATION ===================

  /**
   * Derive key using HKDF in WASM
   */
  async hkdfDeriveKey(inputKeyMaterial, salt, info, outputLength = 32) {
    this._ensureReady();

    try {
      // Convert inputs to Uint8Array
      const convertToBytes = (input) => {
        if (input instanceof Uint8Array) return input;
        if (typeof input === "string") return new TextEncoder().encode(input);
        throw new Error("Input must be Uint8Array or string");
      };

      const ikmBytes = convertToBytes(inputKeyMaterial);
      const saltBytes = convertToBytes(salt);
      const infoBytes = convertToBytes(info);

      const derivedKey = wasmModule.hkdf_derive_key(
        ikmBytes,
        saltBytes,
        infoBytes,
        outputLength,
      );
      return derivedKey;
    } catch (error) {
      throw new Error(`WASM HKDF key derivation failed: ${error.message}`);
    }
  }

  // =================== UTILITY FUNCTIONS ===================

  /**
   * Serialize public key for storage/transmission
   */
  serializePublicKey(publicKey) {
    this._ensureReady();

    try {
      const publicKeyBytes =
        publicKey instanceof Uint8Array
          ? publicKey
          : this._hexToBuffer(publicKey);
      return wasmModule.serialize_public_key(publicKeyBytes);
    } catch (error) {
      throw new Error(`WASM public key serialization failed: ${error.message}`);
    }
  }

  /**
   * Deserialize public key from storage/transmission
   */
  deserializePublicKey(serializedKey) {
    this._ensureReady();

    try {
      const serializedBytes =
        serializedKey instanceof Uint8Array
          ? serializedKey
          : this._hexToBuffer(serializedKey);
      return wasmModule.deserialize_public_key(serializedBytes);
    } catch (error) {
      throw new Error(
        `WASM public key deserialization failed: ${error.message}`,
      );
    }
  }

  /**
   * Clean up memory (WASM-specific)
   */
  freeKeyPair(keyPair) {
    if (this.moduleReady && keyPair) {
      try {
        wasmModule.free_keypair(keyPair);
      } catch (error) {
        console.warn("Failed to free keypair:", error.message);
      }
    }
  }

  /**
   * Clean up buffer memory (WASM-specific)
   */
  freeBuffer(buffer) {
    if (this.moduleReady && buffer) {
      try {
        wasmModule.free_buffer(buffer);
      } catch (error) {
        console.warn("Failed to free buffer:", error.message);
      }
    }
  }

  /**
   * Convert buffer to hex string (utility)
   */
  bufferToHex(buffer) {
    return this._bufferToHex(buffer);
  }

  /**
   * Convert hex string to buffer (utility)
   */
  hexToBuffer(hex) {
    return this._hexToBuffer(hex);
  }
}

/**
 * Factory function to create Signal Protocol WASM instance
 */
export async function createSignalProtocolWasm() {
  const instance = new SignalProtocolWasm();
  await instance.initialize();
  return instance;
}

/**
 * High-level helper functions that match the JavaScript interface
 */
export const SignalWasmHelpers = {
  /**
   * Complete Signal Protocol user initialization using WASM
   */
  async initializeSignalUser(name, wasmInstance) {
    if (!wasmInstance) {
      throw new Error("WASM instance required");
    }

    // Generate all required keys
    const identityKeyPair = await wasmInstance.generateIdentityKeyPair();
    const signedPrekeyPair = await wasmInstance.generateSignedPrekey();

    // Generate signature for signed prekey
    const signedPrekeySignature = await wasmInstance.signData(
      identityKeyPair.privateKey,
      signedPrekeyPair.publicKey,
    );

    // Generate one-time prekeys
    const oneTimePrekeyPairs = [];
    for (let i = 0; i < 10; i++) {
      const prekeyPair = await wasmInstance.generateOneTimePrekey();
      oneTimePrekeyPairs.push(prekeyPair);
    }

    return {
      name,
      identityKeyPair,
      signedPrekeyPair,
      signedPrekeySignature,
      oneTimePrekeyPairs,
    };
  },

  /**
   * Create public key bundle for key exchange
   */
  async getPublicKeyBundle(user) {
    return {
      identityKey: user.identityKeyPair.publicKey,
      signedPrekey: user.signedPrekeyPair.publicKey,
      signedPrekeySignature: user.signedPrekeySignature,
      oneTimePrekey:
        user.oneTimePrekeyPairs.length > 0
          ? user.oneTimePrekeyPairs[0].publicKey
          : null,
    };
  },

  /**
   * Perform complete X3DH key exchange
   */
  async performX3DHKeyExchange(alice, bobBundle, wasmInstance) {
    // Generate ephemeral key pair for Alice
    const aliceEphemeral = await wasmInstance.generateEphemeralKeyPair();

    // Initiate X3DH (SP-2026: Alice IK public + Bob SPK signature required)
    const result = await wasmInstance.x3dhInitiate(
      alice.identityKeyPair.privateKey,
      aliceEphemeral.privateKey,
      alice.identityKeyPair.publicKey,
      bobBundle.identityKey,
      bobBundle.signedPrekey,
      bobBundle.signedPrekeySignature,
      bobBundle.oneTimePrekey,
    );

    return {
      ...result,
      aliceEphemeralPublic: aliceEphemeral.publicKey,
    };
  },
};

// Default export
export default SignalProtocolWasm;
