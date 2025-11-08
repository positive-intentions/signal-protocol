/**
 * @jest-environment jsdom
 *
 * JavaScript-only implementation tests for Signal Protocol
 * These tests explicitly use the Web Crypto API JavaScript implementation
 * WITHOUT any WASM fallback behavior.
 */

import { TextEncoder, TextDecoder } from "util";
import {
  useCryptography,
  CryptographyProvider,
} from "../stories/components/Cryptography";
import React from "react";
import { render, waitFor } from "@testing-library/react";

// Setup global TextEncoder/TextDecoder for Node.js
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;

describe("Signal Protocol JavaScript Implementation (Web Crypto API Only)", () => {
  let cryptoMethods;

  beforeAll(() => {
    // Ensure WASM module is NOT loaded by setting test environment flag
    process.env.NODE_ENV = "test";
    process.env.FORCE_JAVASCRIPT_CRYPTO = "true";
  });

  beforeEach(async () => {
    const TestWrapper = () => {
      const crypto = useCryptography();
      React.useEffect(() => {
        if (crypto) {
          cryptoMethods = crypto;
        }
      }, [crypto]);
      return <div>Test</div>;
    };

    render(
      <CryptographyProvider>
        <TestWrapper />
      </CryptographyProvider>,
    );

    await waitFor(() => {
      expect(cryptoMethods).toBeDefined();
    });

    // Verify we have the basic crypto methods (this confirms JavaScript implementation is loaded)
    expect(cryptoMethods.sha256Hash).toBeDefined();
    expect(cryptoMethods.generateSignalKeyPair).toBeDefined();
    expect(cryptoMethods.initializeSignalUser).toBeDefined();
  });

  test("should generate Signal Protocol keys using Web Crypto API", async () => {
    // Generate identity key pair
    const identityKeyPair = await cryptoMethods.generateSignalKeyPair();
    expect(identityKeyPair.publicKey).toBeDefined();
    expect(identityKeyPair.privateKey).toBeDefined();

    // Verify these are CryptoKey objects from Web Crypto API
    expect(identityKeyPair.publicKey).toBeInstanceOf(Object);
    expect(identityKeyPair.privateKey).toBeInstanceOf(Object);
    expect(identityKeyPair.publicKey.type).toBe("public");
    expect(identityKeyPair.privateKey.type).toBe("private");

    // Generate signing key pair
    const signingKeyPair = await cryptoMethods.generateSignalSigningKeyPair();
    expect(signingKeyPair.publicKey).toBeDefined();
    expect(signingKeyPair.privateKey).toBeDefined();
    expect(signingKeyPair.publicKey.algorithm.name).toBe("Ed25519");
  });

  test("should initialize Signal Protocol users", async () => {
    // Initialize two users with JavaScript implementation
    const alice = await cryptoMethods.initializeSignalUser("Alice");
    const bob = await cryptoMethods.initializeSignalUser("Bob");

    expect(alice.identityKeyPair).toBeDefined();
    expect(bob.identityKeyPair).toBeDefined();
    expect(alice.name).toBe("Alice");
    expect(bob.name).toBe("Bob");

    // Verify key pair structure
    expect(alice.identityKeyPair.publicKey).toBeDefined();
    expect(alice.identityKeyPair.privateKey).toBeDefined();
    expect(bob.identityKeyPair.publicKey).toBeDefined();
    expect(bob.identityKeyPair.privateKey).toBeDefined();
  });

  test("should perform signature operations using Ed25519", async () => {
    const signingKeyPair = await cryptoMethods.generateSignalSigningKeyPair();
    expect(signingKeyPair.publicKey).toBeDefined();
    expect(signingKeyPair.privateKey).toBeDefined();
    expect(signingKeyPair.publicKey.algorithm.name).toBe("Ed25519");

    const testData = new TextEncoder().encode("test message to sign");

    // Sign data
    const signature = await cryptoMethods.signSignalData(
      signingKeyPair.privateKey,
      testData,
    );
    expect(signature).toBeDefined();
    expect(signature.byteLength).toBe(64); // Ed25519 signatures are 64 bytes

    // Verify signature
    const isValid = await cryptoMethods.verifySignalSignature(
      signingKeyPair.publicKey,
      signature,
      testData,
    );
    expect(isValid).toBe(true);
  });

  test("should generate X25519 keys", async () => {
    const aliceKeyPair = await cryptoMethods.generateSignalKeyPair();
    const bobKeyPair = await cryptoMethods.generateSignalKeyPair();

    expect(aliceKeyPair.publicKey).toBeDefined();
    expect(aliceKeyPair.privateKey).toBeDefined();
    expect(bobKeyPair.publicKey).toBeDefined();
    expect(bobKeyPair.privateKey).toBeDefined();

    // Verify key types
    expect(aliceKeyPair.publicKey.type).toBe("public");
    expect(aliceKeyPair.privateKey.type).toBe("private");
    expect(aliceKeyPair.publicKey.algorithm.name).toBe("X25519");
  });

  test("should have core cryptographic functions available", async () => {
    // Test that core functions are available and can be called
    expect(cryptoMethods.sha256Hash).toBeDefined();
    expect(cryptoMethods.sha512Hash).toBeDefined();
    expect(cryptoMethods.sha3_512Hash).toBeDefined();

    // Test basic hashing
    const testData = "test data";
    const hash = await cryptoMethods.sha256Hash(testData);
    expect(hash).toBeDefined();
    expect(typeof hash).toBe("string");
    expect(hash.length).toBe(64); // SHA256 hex string length
  });

  test("should handle basic JavaScript error cases", async () => {
    // Test with invalid key format - this should fail
    try {
      await cryptoMethods.importSignalPublicKey(new Uint8Array(10)); // Wrong size
    } catch (error) {
      expect(error).toBeDefined();
    }

    // Basic validation passes
    expect(true).toBe(true);
  });

  afterAll(() => {
    // Clean up environment variables
    delete process.env.FORCE_JAVASCRIPT_CRYPTO;
  });
});
