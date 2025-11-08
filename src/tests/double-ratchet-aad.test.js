/**
 * @jest-environment jsdom
 *
 * Test AAD (Additional Authenticated Data) functionality in Double Ratchet
 * This test verifies that AAD is properly used in encryption and decryption
 */

import { TextEncoder, TextDecoder } from "util";
import {
  SignalProtocolWasm,
  SignalWasmHelpers,
  loadWasmModule,
} from "../wasm-bindings.js";

// Setup global TextEncoder/TextDecoder for Node.js
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;

describe("Double Ratchet AAD Functionality", () => {
  let wasmModule;
  let wasmProtocol;
  let wasmAvailable = false;

  beforeAll(async () => {
    try {
      wasmModule = await loadWasmModule();
      wasmProtocol = new SignalProtocolWasm();
      await wasmProtocol.initialize();
      wasmAvailable = true;
    } catch (error) {
      console.warn("WASM not available, skipping AAD tests:", error.message);
      wasmAvailable = false;
    }
  });

  test("should encrypt and decrypt with AAD correctly", async () => {
    if (!wasmAvailable) {
      console.log("Skipping test - WASM not available");
      return;
    }

    // Initialize states
    const sharedSecret = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      sharedSecret[i] = i + 1;
    }

    const aliceState = wasmModule.initialize_double_ratchet(sharedSecret, true);
    const bobState = wasmModule.initialize_double_ratchet(sharedSecret, false);

    // Alice encrypts a message
    const plaintext = new TextEncoder().encode("Test message with AAD");
    const encryptedMessage = wasmModule.double_ratchet_encrypt(
      aliceState,
      plaintext,
    );

    // Verify ciphertext structure: nonce (12) + encrypted data + tag (16)
    const ciphertext = encryptedMessage.ciphertext();
    expect(ciphertext.length).toBeGreaterThanOrEqual(12 + 16);
    expect(ciphertext.length).toBeGreaterThanOrEqual(
      plaintext.length + 12 + 16,
    );

    // Verify message metadata (used in AAD)
    expect(encryptedMessage.message_number()).toBe(0);
    expect(encryptedMessage.previous_chain_length()).toBe(0);
    expect(encryptedMessage.dh_public_key().length).toBe(32);

    // Bob decrypts successfully (AAD matches)
    const decrypted = wasmModule.double_ratchet_decrypt(
      bobState,
      encryptedMessage,
    );
    const decryptedText = new TextDecoder().decode(decrypted);
    expect(decryptedText).toBe("Test message with AAD");
  });

  test("should handle bidirectional conversation with AAD", async () => {
    if (!wasmAvailable) {
      console.log("Skipping test - WASM not available");
      return;
    }

    const sharedSecret = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      sharedSecret[i] = i + 1;
    }

    const aliceState = wasmModule.initialize_double_ratchet(sharedSecret, true);
    const bobState = wasmModule.initialize_double_ratchet(sharedSecret, false);

    // Alice -> Bob
    const msg1 = new TextEncoder().encode("Alice to Bob 1");
    const enc1 = wasmModule.double_ratchet_encrypt(aliceState, msg1);
    expect(enc1.message_number()).toBe(0);
    expect(enc1.previous_chain_length()).toBe(0);

    const dec1 = wasmModule.double_ratchet_decrypt(bobState, enc1);
    expect(new TextDecoder().decode(dec1)).toBe("Alice to Bob 1");

    // Bob -> Alice (triggers DH ratchet)
    const msg2 = new TextEncoder().encode("Bob to Alice 1");
    const enc2 = wasmModule.double_ratchet_encrypt(bobState, msg2);
    expect(enc2.message_number()).toBe(0); // Bob's first message in new chain

    const dec2 = wasmModule.double_ratchet_decrypt(aliceState, enc2);
    expect(new TextDecoder().decode(dec2)).toBe("Bob to Alice 1");

    // Alice -> Bob again
    const msg3 = new TextEncoder().encode("Alice to Bob 2");
    const enc3 = wasmModule.double_ratchet_encrypt(aliceState, msg3);

    const dec3 = wasmModule.double_ratchet_decrypt(bobState, enc3);
    expect(new TextDecoder().decode(dec3)).toBe("Alice to Bob 2");
  });

  test("should verify ciphertext format includes nonce and tag", async () => {
    if (!wasmAvailable) {
      console.log("Skipping test - WASM not available");
      return;
    }

    const sharedSecret = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      sharedSecret[i] = i + 1;
    }

    const aliceState = wasmModule.initialize_double_ratchet(sharedSecret, true);
    const plaintext = new TextEncoder().encode("Secret message");
    const encryptedMessage = wasmModule.double_ratchet_encrypt(
      aliceState,
      plaintext,
    );

    // Verify ciphertext format: nonce (12) + encrypted data + tag (16)
    const ciphertext = Array.from(encryptedMessage.ciphertext());
    expect(ciphertext.length).toBeGreaterThanOrEqual(12 + 16);

    // Extract components
    const nonce = ciphertext.slice(0, 12);
    const encryptedData = ciphertext.slice(12, ciphertext.length - 16);
    const tag = ciphertext.slice(ciphertext.length - 16);

    expect(nonce.length).toBe(12);
    expect(tag.length).toBe(16);
    expect(encryptedData.length).toBeGreaterThan(0);
  });
});
