/**
 * @jest-environment jsdom
 *
 * Test that reproduces the bidirectional Double Ratchet issue
 * where the third message fails due to root key/chain key mismatch
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

describe("Double Ratchet Bidirectional Multiple Messages", () => {
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
      console.warn("WASM not available, skipping tests:", error.message);
      wasmAvailable = false;
    }
  });

  test("should handle bidirectional conversation with multiple DH ratchet steps", async () => {
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

    // Message 1: Alice -> Bob (triggers DH ratchet on Bob's side)
    const msg1 = new TextEncoder().encode("Message 1");
    const enc1 = wasmModule.double_ratchet_encrypt(aliceState, msg1);
    const dec1 = wasmModule.double_ratchet_decrypt(bobState, enc1);
    expect(new TextDecoder().decode(dec1)).toBe("Message 1");

    // Message 2: Bob -> Alice (triggers DH ratchet on Alice's side)
    const msg2 = new TextEncoder().encode("Message 2");
    const enc2 = wasmModule.double_ratchet_encrypt(bobState, msg2);
    const dec2 = wasmModule.double_ratchet_decrypt(aliceState, enc2);
    expect(new TextDecoder().decode(dec2)).toBe("Message 2");

    // Message 3: Alice -> Bob (should work but currently fails)
    const msg3 = new TextEncoder().encode("Message 3");
    const enc3 = wasmModule.double_ratchet_encrypt(aliceState, msg3);

    // This should not throw - if it does, the test will fail
    const dec3 = wasmModule.double_ratchet_decrypt(bobState, enc3);
    expect(new TextDecoder().decode(dec3)).toBe("Message 3");
  });

  test("should keep root keys synchronized after bidirectional exchange", async () => {
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

    // After initialization, root keys should match
    const aliceRoot1 = Array.from(aliceState.root_key());
    const bobRoot1 = Array.from(bobState.root_key());
    expect(aliceRoot1).toEqual(bobRoot1);

    // Message 1: Alice -> Bob
    const msg1 = new TextEncoder().encode("Message 1");
    const enc1 = wasmModule.double_ratchet_encrypt(aliceState, msg1);
    wasmModule.double_ratchet_decrypt(bobState, enc1);

    // Message 2: Bob -> Alice
    const msg2 = new TextEncoder().encode("Message 2");
    const enc2 = wasmModule.double_ratchet_encrypt(bobState, msg2);
    wasmModule.double_ratchet_decrypt(aliceState, enc2);

    // After second message, root keys should be synchronized
    const aliceRoot2 = Array.from(aliceState.root_key());
    const bobRoot2 = Array.from(bobState.root_key());
    expect(aliceRoot2).toEqual(bobRoot2);
  });
});
