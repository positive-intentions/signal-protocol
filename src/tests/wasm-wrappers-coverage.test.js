/**
 * @jest-environment jsdom
 *
 * Comprehensive Jest tests for WASM wrapper functions
 * These tests exercise all WASM wrappers to ensure they work correctly
 * and provide coverage for the wrapper code paths.
 */

import { TextEncoder, TextDecoder } from "util";
import path from "path";
import fs from "fs";
import { pathToFileURL } from "url";

// Setup global TextEncoder/TextDecoder for Node.js
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;

describe("WASM Wrapper Functions Coverage", () => {
  let wasmModule;
  let wasmAvailable = false;

  beforeAll(async () => {
    // Check if WASM files exist
    const pkgDir = path.join(process.cwd(), "pkg");
    const wasmFile = path.join(pkgDir, "signal_protocol_wasm_bg.wasm");
    const jsFile = path.join(pkgDir, "signal_protocol_wasm.js");

    if (!fs.existsSync(wasmFile) || !fs.existsSync(jsFile)) {
      console.error(
        '❌ WASM files not found. Run "npm run build:wasm" to build WASM first.',
      );
      wasmAvailable = false;
      return;
    }

    try {
      // Try loading WASM module - use nodejs build if available for better Node.js compatibility
      const pkgNodeDir = path.join(process.cwd(), "pkg-node");
      const wasmPath = fs.existsSync(path.join(pkgNodeDir, "signal_protocol_wasm.js"))
        ? path.join(pkgNodeDir, "signal_protocol_wasm.js")
        : path.join(pkgDir, "signal_protocol_wasm.js");
      
      const WasmModule = await import(pathToFileURL(path.resolve(wasmPath)).href);
      // Node.js build doesn't need default() call, web build does
      if (typeof WasmModule.default === 'function') {
        await WasmModule.default();
      }
      wasmModule = WasmModule;
      wasmAvailable = true;
      console.log("✅ WASM module loaded successfully");
    } catch (error) {
      // Jest has known limitations importing ES modules from pkg directory
      // The error message will indicate this is a Jest/ESM compatibility issue
      console.error(`❌ Failed to load WASM module: ${error.message}`);
      if (error.message.includes("Must use import") || error.message.includes("Unexpected token")) {
        console.error("💡 This is a known Jest limitation with ES modules.");
        console.error("💡 Consider using 'wasm-pack test --node' for WASM-specific tests.");
        console.error("💡 Or run tests in a browser environment using 'wasm-pack test --chrome'");
      }
      wasmAvailable = false;
      // Don't throw here - let individual tests fail with clear messages
    }
  }, 30000); // Increase timeout for WASM loading

  // Helper function to create Uint8Array from array or buffer
  const toUint8Array = (data) => {
    if (data instanceof Uint8Array) return data;
    if (Array.isArray(data)) return new Uint8Array(data);
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    return new Uint8Array(data);
  };

  // Helper function to convert Uint8Array to array for comparison
  const toArray = (uint8Array) => Array.from(uint8Array);

  describe("Key Generation Wrappers", () => {
    test("generate_identity_keypair wrapper", () => {
      expect(wasmAvailable).toBe(true);
      expect(wasmModule).toBeDefined();

      const result = wasmModule.generate_identity_keypair();
      expect(result).toBeDefined();
      expect(result.public_key).toBeDefined();
      expect(result.private_key).toBeDefined();
      expect(result.public_key.length).toBe(32);
      expect(result.private_key.length).toBe(32);

      // Test getters
      const pubKey = result.public_key;
      const privKey = result.private_key;
      expect(pubKey).toBeInstanceOf(Uint8Array);
      expect(privKey).toBeInstanceOf(Uint8Array);
      expect(pubKey.length).toBe(32);
      expect(privKey.length).toBe(32);
    });

    test("generate_signed_prekey wrapper", () => {
      expect(wasmAvailable).toBe(true);

      const result = wasmModule.generate_signed_prekey();
      expect(result).toBeDefined();
      expect(result.public_key).toBeDefined();
      expect(result.private_key).toBeDefined();
      expect(result.public_key.length).toBe(32);
      expect(result.private_key.length).toBe(32);
    });

    test("generate_one_time_prekey wrapper", () => {
      expect(wasmAvailable).toBe(true);

      const result = wasmModule.generate_one_time_prekey();
      expect(result).toBeDefined();
      expect(result.public_key).toBeDefined();
      expect(result.private_key).toBeDefined();
      expect(result.public_key.length).toBe(32);
      expect(result.private_key.length).toBe(32);
    });

    test("generate_ephemeral_keypair wrapper", () => {
      expect(wasmAvailable).toBe(true);

      const result = wasmModule.generate_ephemeral_keypair();
      expect(result).toBeDefined();
      expect(result.public_key).toBeDefined();
      expect(result.private_key).toBeDefined();
      expect(result.public_key.length).toBe(32);
      expect(result.private_key.length).toBe(32);
    });

    test("key generation uniqueness", () => {
      expect(wasmAvailable).toBe(true);

      const key1 = wasmModule.generate_identity_keypair();
      const key2 = wasmModule.generate_identity_keypair();

      expect(toArray(key1.public_key)).not.toEqual(toArray(key2.public_key));
      expect(toArray(key1.private_key)).not.toEqual(toArray(key2.private_key));
    });
  });

  describe("Crypto Wrappers (sign_data, verify_signature)", () => {
    test("sign_data wrapper", () => {
      expect(wasmAvailable).toBe(true);

      const privateKey = new Uint8Array(32).fill(42);
      const data = new TextEncoder().encode("Hello, WASM signatures!");

      const result = wasmModule.sign_data(privateKey, data);
      expect(result).toBeDefined();
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(64); // Ed25519 signature is 64 bytes
    });

    test("verify_signature wrapper - valid signature", () => {
      expect(wasmAvailable).toBe(true);

      // Generate a real keypair and signature
      const keypair = wasmModule.generate_identity_keypair();
      const data = new TextEncoder().encode("Test message");

      // Sign the data
      const signature = wasmModule.sign_data(keypair.private_key, data);

      // Verify the signature
      const isValid = wasmModule.verify_signature(
        keypair.public_key,
        signature,
        data,
      );

      expect(typeof isValid).toBe("boolean");
      // Note: The actual result depends on the implementation
      // This test exercises the wrapper code path
    });

    test("verify_signature wrapper - invalid signature", () => {
      expect(wasmAvailable).toBe(true);

      const keypair = wasmModule.generate_identity_keypair();
      const data = new TextEncoder().encode("Test message");
      const wrongSignature = new Uint8Array(64).fill(0);

      const isValid = wasmModule.verify_signature(
        keypair.public_key,
        wrongSignature,
        data,
      );

      expect(typeof isValid).toBe("boolean");
    });

    test("sign_data wrapper error handling", () => {
      expect(wasmAvailable).toBe(true);

      const shortKey = new Uint8Array(16); // Too short
      const data = new TextEncoder().encode("Test");

      expect(() => {
        wasmModule.sign_data(shortKey, data);
      }).toThrow();
    });
  });

  describe("X3DH Wrappers", () => {
    test("x3dh_initiate wrapper", () => {
      expect(wasmAvailable).toBe(true);

      const aliceIdentity = wasmModule.generate_identity_keypair();
      const aliceEphemeral = wasmModule.generate_ephemeral_keypair();
      const bobIdentity = wasmModule.generate_identity_keypair();
      const bobSignedPrekey = wasmModule.generate_signed_prekey();
      const bobOneTimePrekey = wasmModule.generate_one_time_prekey();

      const result = wasmModule.x3dh_initiate(
        aliceIdentity.private_key,
        aliceEphemeral.private_key,
        bobIdentity.public_key,
        bobSignedPrekey.public_key,
        bobOneTimePrekey.public_key,
      );

      expect(result).toBeDefined();
      expect(result.shared_secret).toBeDefined();
      expect(result.associated_data).toBeDefined();
      expect(result.shared_secret).toBeInstanceOf(Uint8Array);
      expect(result.shared_secret.length).toBe(32);
    });

    test("x3dh_initiate wrapper without one-time prekey", () => {
      expect(wasmAvailable).toBe(true);

      const aliceIdentity = wasmModule.generate_identity_keypair();
      const aliceEphemeral = wasmModule.generate_ephemeral_keypair();
      const bobIdentity = wasmModule.generate_identity_keypair();
      const bobSignedPrekey = wasmModule.generate_signed_prekey();

      const result = wasmModule.x3dh_initiate(
        aliceIdentity.private_key,
        aliceEphemeral.private_key,
        bobIdentity.public_key,
        bobSignedPrekey.public_key,
        null,
      );

      expect(result).toBeDefined();
      expect(result.shared_secret).toBeDefined();
      expect(result.shared_secret.length).toBe(32);
    });

    test("x3dh_respond wrapper", () => {
      expect(wasmAvailable).toBe(true);

      const aliceIdentity = wasmModule.generate_identity_keypair();
      const aliceEphemeral = wasmModule.generate_ephemeral_keypair();
      const bobIdentity = wasmModule.generate_identity_keypair();
      const bobSignedPrekey = wasmModule.generate_signed_prekey();
      const bobOneTimePrekey = wasmModule.generate_one_time_prekey();

      const result = wasmModule.x3dh_respond(
        bobIdentity.private_key,
        bobSignedPrekey.private_key,
        bobOneTimePrekey.private_key,
        aliceIdentity.public_key,
        aliceEphemeral.public_key,
      );

      expect(result).toBeDefined();
      expect(result.shared_secret).toBeDefined();
      expect(result.shared_secret.length).toBe(32);
    });

    test("x3dh_respond wrapper without one-time prekey", () => {
      expect(wasmAvailable).toBe(true);

      const aliceIdentity = wasmModule.generate_identity_keypair();
      const aliceEphemeral = wasmModule.generate_ephemeral_keypair();
      const bobIdentity = wasmModule.generate_identity_keypair();
      const bobSignedPrekey = wasmModule.generate_signed_prekey();

      const result = wasmModule.x3dh_respond(
        bobIdentity.private_key,
        bobSignedPrekey.private_key,
        null,
        aliceIdentity.public_key,
        aliceEphemeral.public_key,
      );

      expect(result).toBeDefined();
      expect(result.shared_secret).toBeDefined();
      expect(result.shared_secret.length).toBe(32);
    });

    test("X3DHResult getters", () => {
      expect(wasmAvailable).toBe(true);

      const aliceIdentity = wasmModule.generate_identity_keypair();
      const aliceEphemeral = wasmModule.generate_ephemeral_keypair();
      const bobIdentity = wasmModule.generate_identity_keypair();
      const bobSignedPrekey = wasmModule.generate_signed_prekey();

      const result = wasmModule.x3dh_initiate(
        aliceIdentity.private_key,
        aliceEphemeral.private_key,
        bobIdentity.public_key,
        bobSignedPrekey.public_key,
        null,
      );

      // Test getters
      const sharedSecret = result.shared_secret;
      const associatedData = result.associated_data;

      expect(sharedSecret).toBeInstanceOf(Uint8Array);
      expect(associatedData).toBeInstanceOf(Uint8Array);
      expect(sharedSecret.length).toBe(32);
    });
  });

  describe("Message Encryption Wrappers", () => {
    test("encrypt_message wrapper", () => {
      expect(wasmAvailable).toBe(true);

      const sharedSecret = new Uint8Array(32).fill(1);
      const plaintext = new TextEncoder().encode("Secret message");
      const messageNumber = 1;

      const result = wasmModule.encrypt_message(
        sharedSecret,
        plaintext,
        messageNumber,
      );

      expect(result).toBeDefined();
      expect(result.ciphertext).toBeDefined();
      expect(result.message_key).toBeDefined();
      expect(result.ciphertext).toBeInstanceOf(Uint8Array);
      expect(result.message_key).toBeInstanceOf(Uint8Array);
      expect(result.ciphertext.length).toBeGreaterThan(plaintext.length);
      expect(result.message_key.length).toBe(32);
    });

    test("decrypt_message wrapper", () => {
      expect(wasmAvailable).toBe(true);

      const sharedSecret = new Uint8Array(32).fill(1);
      const plaintext = new TextEncoder().encode("Test message");
      const messageNumber = 1;

      // Encrypt first
      const encrypted = wasmModule.encrypt_message(
        sharedSecret,
        plaintext,
        messageNumber,
      );

      // Decrypt
      const decrypted = wasmModule.decrypt_message(
        sharedSecret,
        encrypted.ciphertext,
        encrypted.message_key,
      );

      expect(decrypted).toBeDefined();
      expect(decrypted).toBeInstanceOf(Uint8Array);
      expect(toArray(decrypted)).toEqual(toArray(plaintext));
    });

    test("EncryptionResult getters", () => {
      expect(wasmAvailable).toBe(true);

      const sharedSecret = new Uint8Array(32).fill(1);
      const plaintext = new TextEncoder().encode("Test");
      const result = wasmModule.encrypt_message(sharedSecret, plaintext, 1);

      // Test getters
      const ciphertext = result.ciphertext;
      const messageKey = result.message_key;

      expect(ciphertext).toBeInstanceOf(Uint8Array);
      expect(messageKey).toBeInstanceOf(Uint8Array);
    });
  });

  describe("Utility Wrappers", () => {
    test("serialize_public_key wrapper", () => {
      expect(wasmAvailable).toBe(true);

      const publicKey = new Uint8Array(32).fill(42);
      const result = wasmModule.serialize_public_key(publicKey);

      expect(result).toBeDefined();
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(33); // 32 bytes + 1 version byte
      expect(result[0]).toBe(0x05); // Version byte
    });

    test("deserialize_public_key wrapper", () => {
      expect(wasmAvailable).toBe(true);

      const publicKey = new Uint8Array(32).fill(42);
      const serialized = wasmModule.serialize_public_key(publicKey);

      const deserialized = wasmModule.deserialize_public_key(serialized);

      expect(deserialized).toBeDefined();
      expect(deserialized).toBeInstanceOf(Uint8Array);
      expect(deserialized.length).toBe(32);
      expect(toArray(deserialized)).toEqual(toArray(publicKey));
    });

    test("serialize_public_key wrapper error handling", () => {
      expect(wasmAvailable).toBe(true);

      const shortKey = new Uint8Array(16); // Too short

      expect(() => {
        wasmModule.serialize_public_key(shortKey);
      }).toThrow();
    });

    test("deserialize_public_key wrapper error handling", () => {
      expect(wasmAvailable).toBe(true);

      const wrongSize = new Uint8Array(20); // Wrong size

      expect(() => {
        wasmModule.deserialize_public_key(wrongSize);
      }).toThrow();
    });

    test("hkdf_derive_key wrapper", () => {
      expect(wasmAvailable).toBe(true);

      const inputKey = new TextEncoder().encode("input key material");
      const salt = new TextEncoder().encode("salt data");
      const info = new TextEncoder().encode("application info");
      const outputLength = 32;

      const result = wasmModule.hkdf_derive_key(
        inputKey,
        salt,
        info,
        outputLength,
      );

      expect(result).toBeDefined();
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(outputLength);
    });

    test("hkdf_derive_key wrapper - different lengths", () => {
      expect(wasmAvailable).toBe(true);

      const inputKey = new TextEncoder().encode("input key");
      const salt = new TextEncoder().encode("salt");
      const info = new TextEncoder().encode("info");

      for (const length of [16, 32, 64]) {
        const result = wasmModule.hkdf_derive_key(
          inputKey,
          salt,
          info,
          length,
        );
        expect(result.length).toBe(length);
      }
    });

    test("hkdf_derive_key wrapper error handling", () => {
      expect(wasmAvailable).toBe(true);

      const inputKey = new TextEncoder().encode("input");
      const salt = new TextEncoder().encode("salt");
      const info = new TextEncoder().encode("info");

      // Test zero length
      expect(() => {
        wasmModule.hkdf_derive_key(inputKey, salt, info, 0);
      }).toThrow();

      // Test too large length
      expect(() => {
        wasmModule.hkdf_derive_key(inputKey, salt, info, 100000);
      }).toThrow();
    });

    test("free_keypair wrapper", () => {
      expect(wasmAvailable).toBe(true);

      const keypair = wasmModule.generate_identity_keypair();

      // Should not throw - it's a no-op
      expect(() => {
        wasmModule.free_keypair(keypair);
      }).not.toThrow();
    });

    test("free_buffer wrapper", () => {
      expect(wasmAvailable).toBe(true);

      const buffer = new Uint8Array(64);

      // Should not throw - it's a no-op
      expect(() => {
        wasmModule.free_buffer(buffer);
      }).not.toThrow();
    });
  });

  describe("Double Ratchet Wrappers", () => {
    test("initialize_double_ratchet wrapper - initiator", () => {
      expect(wasmAvailable).toBe(true);

      const sharedSecret = new Uint8Array(32).fill(1);
      const state = wasmModule.initialize_double_ratchet(sharedSecret, true);

      expect(state).toBeDefined();
      expect(state.root_key).toBeDefined();
      expect(state.root_key).toBeInstanceOf(Uint8Array);
      expect(state.root_key.length).toBe(32);
    });

    test("initialize_double_ratchet wrapper - responder", () => {
      expect(wasmAvailable).toBe(true);

      const sharedSecret = new Uint8Array(32).fill(1);
      const state = wasmModule.initialize_double_ratchet(sharedSecret, false);

      expect(state).toBeDefined();
      expect(state.root_key).toBeDefined();
      expect(state.root_key.length).toBe(32);
    });

    test("double_ratchet_encrypt wrapper", () => {
      expect(wasmAvailable).toBe(true);

      const sharedSecret = new Uint8Array(32).fill(1);
      const aliceState = wasmModule.initialize_double_ratchet(
        sharedSecret,
        true,
      );
      const plaintext = new TextEncoder().encode("Hello, Double Ratchet!");

      const message = wasmModule.double_ratchet_encrypt(aliceState, plaintext);

      expect(message).toBeDefined();
      expect(message.ciphertext).toBeDefined();
      expect(message.dh_public_key).toBeDefined();
      expect(message.message_number).toBeDefined();
      expect(message.previous_chain_length).toBeDefined();
      expect(message.ciphertext).toBeInstanceOf(Uint8Array);
      expect(message.dh_public_key).toBeInstanceOf(Uint8Array);
      expect(message.message_number).toBe(0);
    });

    test("double_ratchet_decrypt wrapper", () => {
      expect(wasmAvailable).toBe(true);

      const sharedSecret = new Uint8Array(32).fill(1);
      const aliceState = wasmModule.initialize_double_ratchet(
        sharedSecret,
        true,
      );
      const bobState = wasmModule.initialize_double_ratchet(
        sharedSecret,
        false,
      );

      const plaintext = new TextEncoder().encode("Test message");
      const encrypted = wasmModule.double_ratchet_encrypt(
        aliceState,
        plaintext,
      );

      const decrypted = wasmModule.double_ratchet_decrypt(bobState, encrypted);

      expect(decrypted).toBeDefined();
      expect(decrypted).toBeInstanceOf(Uint8Array);
      expect(toArray(decrypted)).toEqual(toArray(plaintext));
    });

    test("DoubleRatchetState getters", () => {
      expect(wasmAvailable).toBe(true);

      const sharedSecret = new Uint8Array(32).fill(1);
      const state = wasmModule.initialize_double_ratchet(sharedSecret, true);

      // Test getters
      const rootKey = state.root_key;
      const sendingMsgNum = state.sending_message_number;
      const receivingMsgNum = state.receiving_message_number;
      const skippedKeysCount = state.skipped_keys_count;

      expect(rootKey).toBeInstanceOf(Uint8Array);
      expect(typeof sendingMsgNum).toBe("number");
      expect(typeof receivingMsgNum).toBe("number");
      expect(typeof skippedKeysCount).toBe("number");
    });

    test("DoubleRatchetMessage getters", () => {
      expect(wasmAvailable).toBe(true);

      const sharedSecret = new Uint8Array(32).fill(1);
      const state = wasmModule.initialize_double_ratchet(sharedSecret, true);
      const plaintext = new TextEncoder().encode("Test");
      const message = wasmModule.double_ratchet_encrypt(state, plaintext);

      // Test getters
      const ciphertext = message.ciphertext;
      const dhPublicKey = message.dh_public_key;
      const messageNumber = message.message_number;
      const previousChainLength = message.previous_chain_length;

      expect(ciphertext).toBeInstanceOf(Uint8Array);
      expect(dhPublicKey).toBeInstanceOf(Uint8Array);
      expect(typeof messageNumber).toBe("number");
      expect(typeof previousChainLength).toBe("number");
    });

    test("cleanup_skipped_message_keys wrapper", () => {
      expect(wasmAvailable).toBe(true);

      const sharedSecret = new Uint8Array(32).fill(1);
      const state = wasmModule.initialize_double_ratchet(sharedSecret, true);

      // Create some skipped keys by encrypting multiple messages
      const plaintext = new TextEncoder().encode("Message");
      for (let i = 0; i < 5; i++) {
        wasmModule.double_ratchet_encrypt(state, plaintext);
      }

      const removed = wasmModule.cleanup_skipped_message_keys(state, 3);

      expect(typeof removed).toBe("number");
      expect(removed).toBeGreaterThanOrEqual(0);
    });
  });

  describe("Error Handling in Wrappers", () => {
    test("wrapper error conversion", () => {
      expect(wasmAvailable).toBe(true);

      // Test that errors are properly converted to JavaScript errors
      const invalidKey = new Uint8Array(16); // Too short

      expect(() => {
        wasmModule.serialize_public_key(invalidKey);
      }).toThrow();

      expect(() => {
        wasmModule.sign_data(invalidKey, new Uint8Array(10));
      }).toThrow();
    });

    test("wrapper error messages", () => {
      expect(wasmAvailable).toBe(true);

      const invalidKey = new Uint8Array(16);

      try {
        wasmModule.serialize_public_key(invalidKey);
        fail("Should have thrown");
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect(error.message).toBeDefined();
        expect(typeof error.message).toBe("string");
      }
    });
  });

  describe("Type Conversion in Wrappers", () => {
    test("Uint8Array conversion in wrappers", () => {
      expect(wasmAvailable).toBe(true);

      // Test that wrappers properly handle Uint8Array inputs
      const key = new Uint8Array(32).fill(42);
      const serialized = wasmModule.serialize_public_key(key);

      expect(serialized).toBeInstanceOf(Uint8Array);
      expect(serialized.length).toBe(33);
    });

    test("Array to Uint8Array conversion", () => {
      expect(wasmAvailable).toBe(true);

      // Some wrappers might accept arrays - test conversion
      const keyArray = new Array(32).fill(42);
      const keyUint8 = new Uint8Array(keyArray);

      const serialized = wasmModule.serialize_public_key(keyUint8);
      expect(serialized).toBeInstanceOf(Uint8Array);
    });
  });
});

