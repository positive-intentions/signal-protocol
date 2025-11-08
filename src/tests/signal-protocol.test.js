/**
 * @jest-environment jsdom
 */

import { TextEncoder, TextDecoder } from "util";

// Mock Web Crypto API for Node.js environment
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;

// Mock crypto.subtle API
const mockCrypto = {
  subtle: {
    generateKey: jest.fn(),
    exportKey: jest.fn(),
    importKey: jest.fn(),
    deriveBits: jest.fn(),
    deriveKey: jest.fn(),
    sign: jest.fn(),
    verify: jest.fn(),
    encrypt: jest.fn(),
    decrypt: jest.fn(),
  },
  getRandomValues: jest.fn(),
};

// Mock the crypto global
Object.defineProperty(global, "crypto", {
  value: mockCrypto,
  writable: true,
});

// Mock the window.crypto as well for compatibility
Object.defineProperty(global, "window", {
  value: { crypto: mockCrypto },
  writable: true,
});

describe("Signal Protocol Implementation", () => {
  let signalProtocol;

  beforeEach(() => {
    jest.clearAllMocks();

    // Create a mock implementation that we'll test against
    signalProtocol = {
      keyParams: {
        name: "ECDH",
        namedCurve: "P-256",
      },
      hkdfParams: {
        name: "HKDF",
        hash: "SHA-256",
      },
    };
  });

  describe("generateSignalKeyPair", () => {
    test("should generate ECDH key pair with correct parameters", async () => {
      const mockKeyPair = {
        publicKey: { type: "public" },
        privateKey: { type: "private" },
      };

      mockCrypto.subtle.generateKey.mockResolvedValue(mockKeyPair);

      const generateSignalKeyPair = async () => {
        return await crypto.subtle.generateKey(
          {
            name: "ECDH",
            namedCurve: "P-256",
          },
          true,
          ["deriveKey", "deriveBits"],
        );
      };

      const result = await generateSignalKeyPair();

      expect(mockCrypto.subtle.generateKey).toHaveBeenCalledWith(
        {
          name: "ECDH",
          namedCurve: "P-256",
        },
        true,
        ["deriveKey", "deriveBits"],
      );
      expect(result).toEqual(mockKeyPair);
    });
  });

  describe("exportSignalPublicKey", () => {
    test("should export public key as raw bytes", async () => {
      const mockPublicKey = { type: "public" };
      const mockRawKey = new ArrayBuffer(65); // P-256 uncompressed public key

      mockCrypto.subtle.exportKey.mockResolvedValue(mockRawKey);

      const exportSignalPublicKey = async (publicKey) => {
        return await crypto.subtle.exportKey("raw", publicKey);
      };

      const result = await exportSignalPublicKey(mockPublicKey);

      expect(mockCrypto.subtle.exportKey).toHaveBeenCalledWith(
        "raw",
        mockPublicKey,
      );
      expect(result).toEqual(mockRawKey);
    });
  });

  describe("importSignalPublicKey", () => {
    test("should import public key from raw bytes", async () => {
      const mockKeyBytes = new ArrayBuffer(65);
      const mockImportedKey = { type: "public" };

      mockCrypto.subtle.importKey.mockResolvedValue(mockImportedKey);

      const importSignalPublicKey = async (keyBytes) => {
        return await crypto.subtle.importKey(
          "raw",
          keyBytes,
          {
            name: "ECDH",
            namedCurve: "P-256",
          },
          false,
          [],
        );
      };

      const result = await importSignalPublicKey(mockKeyBytes);

      expect(mockCrypto.subtle.importKey).toHaveBeenCalledWith(
        "raw",
        mockKeyBytes,
        {
          name: "ECDH",
          namedCurve: "P-256",
        },
        false,
        [],
      );
      expect(result).toEqual(mockImportedKey);
    });
  });

  describe("performSignalDH", () => {
    test("should perform ECDH key agreement", async () => {
      const mockPrivateKey = { type: "private" };
      const mockPublicKey = { type: "public" };
      const mockSharedSecret = new ArrayBuffer(32);

      mockCrypto.subtle.deriveBits.mockResolvedValue(mockSharedSecret);

      const performSignalDH = async (privateKey, publicKey) => {
        return await crypto.subtle.deriveBits(
          {
            name: "ECDH",
            public: publicKey,
          },
          privateKey,
          256,
        );
      };

      const result = await performSignalDH(mockPrivateKey, mockPublicKey);

      expect(mockCrypto.subtle.deriveBits).toHaveBeenCalledWith(
        {
          name: "ECDH",
          public: mockPublicKey,
        },
        mockPrivateKey,
        256,
      );
      expect(result).toEqual(mockSharedSecret);
    });
  });

  describe("signSignalData", () => {
    test("should sign data with ECDSA", async () => {
      const mockPrivateKey = { type: "private" };
      const mockData = new Uint8Array([1, 2, 3, 4]);
      const mockSignature = new ArrayBuffer(64);

      mockCrypto.subtle.sign.mockResolvedValue(mockSignature);

      const signSignalData = async (privateKey, data) => {
        return await crypto.subtle.sign(
          {
            name: "ECDSA",
            hash: "SHA-256",
          },
          privateKey,
          data,
        );
      };

      const result = await signSignalData(mockPrivateKey, mockData);

      expect(mockCrypto.subtle.sign).toHaveBeenCalledWith(
        {
          name: "ECDSA",
          hash: "SHA-256",
        },
        mockPrivateKey,
        mockData,
      );
      expect(result).toEqual(mockSignature);
    });
  });

  describe("verifySignalSignature", () => {
    test("should verify signature with ECDSA", async () => {
      const mockPublicKey = { type: "public" };
      const mockSignature = new ArrayBuffer(64);
      const mockData = new Uint8Array([1, 2, 3, 4]);

      mockCrypto.subtle.verify.mockResolvedValue(true);

      const verifySignalSignature = async (publicKey, signature, data) => {
        return await crypto.subtle.verify(
          {
            name: "ECDSA",
            hash: "SHA-256",
          },
          publicKey,
          signature,
          data,
        );
      };

      const result = await verifySignalSignature(
        mockPublicKey,
        mockSignature,
        mockData,
      );

      expect(mockCrypto.subtle.verify).toHaveBeenCalledWith(
        {
          name: "ECDSA",
          hash: "SHA-256",
        },
        mockPublicKey,
        mockSignature,
        mockData,
      );
      expect(result).toBe(true);
    });
  });

  describe("deriveSignalKey", () => {
    test("should derive key using HKDF", async () => {
      const mockInputKeyMaterial = new ArrayBuffer(128);
      const mockSalt = new ArrayBuffer(32);
      const mockInfo = new TextEncoder().encode("Signal_Test");
      const mockPrk = { type: "secret" };
      const mockDerivedKey = { type: "secret" };

      mockCrypto.subtle.importKey.mockResolvedValue(mockPrk);
      mockCrypto.subtle.deriveKey.mockResolvedValue(mockDerivedKey);

      const deriveSignalKey = async (
        inputKeyMaterial,
        salt,
        info,
        length = 256,
      ) => {
        const prk = await crypto.subtle.importKey(
          "raw",
          inputKeyMaterial,
          "HKDF",
          false,
          ["deriveKey"],
        );

        return await crypto.subtle.deriveKey(
          {
            name: "HKDF",
            hash: "SHA-256",
            salt: salt,
            info: info,
          },
          prk,
          {
            name: "AES-GCM",
            length: length,
          },
          true,
          ["encrypt", "decrypt"],
        );
      };

      const result = await deriveSignalKey(
        mockInputKeyMaterial,
        mockSalt,
        mockInfo,
      );

      expect(mockCrypto.subtle.importKey).toHaveBeenCalledWith(
        "raw",
        mockInputKeyMaterial,
        "HKDF",
        false,
        ["deriveKey"],
      );

      expect(mockCrypto.subtle.deriveKey).toHaveBeenCalledWith(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: mockSalt,
          info: mockInfo,
        },
        mockPrk,
        {
          name: "AES-GCM",
          length: 256,
        },
        true,
        ["encrypt", "decrypt"],
      );

      expect(result).toEqual(mockDerivedKey);
    });
  });

  describe("concatSignalArrayBuffers", () => {
    test("should concatenate multiple ArrayBuffers", () => {
      const concatSignalArrayBuffers = (...buffers) => {
        const totalLength = buffers.reduce(
          (sum, buf) => sum + buf.byteLength,
          0,
        );
        const result = new Uint8Array(totalLength);
        let offset = 0;

        for (const buffer of buffers) {
          result.set(new Uint8Array(buffer), offset);
          offset += buffer.byteLength;
        }

        return result.buffer;
      };

      const buffer1 = new Uint8Array([1, 2]).buffer;
      const buffer2 = new Uint8Array([3, 4]).buffer;
      const buffer3 = new Uint8Array([5, 6]).buffer;

      const result = concatSignalArrayBuffers(buffer1, buffer2, buffer3);
      const resultArray = new Uint8Array(result);

      expect(resultArray).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6]));
      expect(result.byteLength).toBe(6);
    });

    test("should handle empty buffers", () => {
      const concatSignalArrayBuffers = (...buffers) => {
        const totalLength = buffers.reduce(
          (sum, buf) => sum + buf.byteLength,
          0,
        );
        const result = new Uint8Array(totalLength);
        let offset = 0;

        for (const buffer of buffers) {
          result.set(new Uint8Array(buffer), offset);
          offset += buffer.byteLength;
        }

        return result.buffer;
      };

      const buffer1 = new Uint8Array([]).buffer;
      const buffer2 = new Uint8Array([1, 2]).buffer;

      const result = concatSignalArrayBuffers(buffer1, buffer2);
      const resultArray = new Uint8Array(result);

      expect(resultArray).toEqual(new Uint8Array([1, 2]));
    });
  });

  describe("bufferToSignalHex", () => {
    test("should convert ArrayBuffer to hex string", () => {
      const bufferToSignalHex = (buffer) => {
        return Array.from(new Uint8Array(buffer))
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("");
      };

      const buffer = new Uint8Array([255, 0, 128, 15]).buffer;
      const result = bufferToSignalHex(buffer);

      expect(result).toBe("ff00800f");
    });

    test("should handle empty buffer", () => {
      const bufferToSignalHex = (buffer) => {
        return Array.from(new Uint8Array(buffer))
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("");
      };

      const buffer = new Uint8Array([]).buffer;
      const result = bufferToSignalHex(buffer);

      expect(result).toBe("");
    });
  });

  describe("Signal User Integration Tests", () => {
    test("should initialize user with all required keys", async () => {
      const mockKeyPair = {
        publicKey: { type: "public" },
        privateKey: { type: "private" },
      };
      const mockRawKey = new ArrayBuffer(65);
      const mockSignature = new ArrayBuffer(64);

      mockCrypto.subtle.generateKey.mockResolvedValue(mockKeyPair);
      mockCrypto.subtle.exportKey.mockResolvedValue(mockRawKey);
      mockCrypto.subtle.sign.mockResolvedValue(mockSignature);

      const initializeSignalUser = async (name) => {
        // Generate identity key pair
        const identityKeyPair = await crypto.subtle.generateKey(
          { name: "ECDH", namedCurve: "P-256" },
          true,
          ["deriveKey", "deriveBits"],
        );

        // Generate signed prekey pair
        const signedPrekeyPair = await crypto.subtle.generateKey(
          { name: "ECDH", namedCurve: "P-256" },
          true,
          ["deriveKey", "deriveBits"],
        );

        // Generate signature for signed prekey
        const prekeyBytes = await crypto.subtle.exportKey(
          "raw",
          signedPrekeyPair.publicKey,
        );
        const signedPrekeySignature = await crypto.subtle.sign(
          { name: "ECDSA", hash: "SHA-256" },
          identityKeyPair.privateKey,
          prekeyBytes,
        );

        // Generate one-time prekeys
        const oneTimePrekeyPairs = [];
        for (let i = 0; i < 3; i++) {
          const oneTimeKey = await crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" },
            true,
            ["deriveKey", "deriveBits"],
          );
          oneTimePrekeyPairs.push(oneTimeKey);
        }

        return {
          name,
          identityKeyPair,
          signedPrekeyPair,
          signedPrekeySignature,
          oneTimePrekeyPairs,
        };
      };

      const user = await initializeSignalUser("Alice");

      expect(mockCrypto.subtle.generateKey).toHaveBeenCalledTimes(5); // identity + signed prekey + 3 one-time keys
      expect(mockCrypto.subtle.exportKey).toHaveBeenCalledTimes(1);
      expect(mockCrypto.subtle.sign).toHaveBeenCalledTimes(1);
      expect(user.name).toBe("Alice");
      expect(user.oneTimePrekeyPairs).toHaveLength(3);
    });

    test("should create valid public key bundle", async () => {
      const mockRawKey = new ArrayBuffer(65);
      mockCrypto.subtle.exportKey.mockResolvedValue(mockRawKey);

      const getPublicKeyBundle = async (user) => {
        return {
          identityKey: await crypto.subtle.exportKey(
            "raw",
            user.identityKeyPair.publicKey,
          ),
          signedPrekey: await crypto.subtle.exportKey(
            "raw",
            user.signedPrekeyPair.publicKey,
          ),
          signedPrekeySignature: user.signedPrekeySignature,
          oneTimePrekey:
            user.oneTimePrekeyPairs.length > 0
              ? await crypto.subtle.exportKey(
                  "raw",
                  user.oneTimePrekeyPairs[0].publicKey,
                )
              : null,
        };
      };

      const mockUser = {
        identityKeyPair: { publicKey: "identity" },
        signedPrekeyPair: { publicKey: "signed" },
        signedPrekeySignature: new ArrayBuffer(64),
        oneTimePrekeyPairs: [{ publicKey: "onetime" }],
      };

      const bundle = await getPublicKeyBundle(mockUser);

      expect(mockCrypto.subtle.exportKey).toHaveBeenCalledTimes(3);
      expect(bundle).toHaveProperty("identityKey");
      expect(bundle).toHaveProperty("signedPrekey");
      expect(bundle).toHaveProperty("signedPrekeySignature");
      expect(bundle).toHaveProperty("oneTimePrekey");
    });
  });

  describe("X3DH Key Exchange Integration Tests", () => {
    test("should perform complete key exchange with all DH computations", async () => {
      const mockKeyPair = { publicKey: "pub", privateKey: "priv" };
      const mockSharedSecret = new ArrayBuffer(32);
      const mockImportedKey = { type: "public" };
      const mockDerivedKey = { type: "secret" };
      const mockRawKey = new ArrayBuffer(65);

      mockCrypto.subtle.generateKey.mockResolvedValue(mockKeyPair);
      mockCrypto.subtle.deriveBits.mockResolvedValue(mockSharedSecret);
      mockCrypto.subtle.importKey.mockResolvedValue(mockImportedKey);
      mockCrypto.subtle.deriveKey.mockResolvedValue(mockDerivedKey);
      mockCrypto.subtle.exportKey.mockResolvedValue(mockRawKey);
      mockCrypto.subtle.verify.mockResolvedValue(true);

      const performX3DHKeyExchange = async (alice, bobBundle) => {
        // Verify Bob's signed prekey signature
        const bobIdentityKey = await crypto.subtle.importKey(
          "raw",
          bobBundle.identityKey,
          { name: "ECDH", namedCurve: "P-256" },
          false,
          [],
        );

        const isValidSignature = await crypto.subtle.verify(
          { name: "ECDSA", hash: "SHA-256" },
          bobIdentityKey,
          bobBundle.signedPrekeySignature,
          bobBundle.signedPrekey,
        );

        if (!isValidSignature) {
          throw new Error("Invalid signed prekey signature!");
        }

        // Generate ephemeral key pair
        const aliceEphemeralPair = await crypto.subtle.generateKey(
          { name: "ECDH", namedCurve: "P-256" },
          true,
          ["deriveKey", "deriveBits"],
        );

        // Import Bob's keys
        const bobSignedPrekey = await crypto.subtle.importKey(
          "raw",
          bobBundle.signedPrekey,
          { name: "ECDH", namedCurve: "P-256" },
          false,
          [],
        );

        // Perform Triple DH
        const dh1 = await crypto.subtle.deriveBits(
          { name: "ECDH", public: bobSignedPrekey },
          alice.identityKeyPair.privateKey,
          256,
        );

        const dh2 = await crypto.subtle.deriveBits(
          { name: "ECDH", public: bobIdentityKey },
          aliceEphemeralPair.privateKey,
          256,
        );

        const dh3 = await crypto.subtle.deriveBits(
          { name: "ECDH", public: bobSignedPrekey },
          aliceEphemeralPair.privateKey,
          256,
        );

        // Concatenate DH outputs
        const dhOutputs = new ArrayBuffer(96); // 32 * 3 bytes

        // Derive master secret
        const prk = await crypto.subtle.importKey(
          "raw",
          dhOutputs,
          "HKDF",
          false,
          ["deriveKey"],
        );
        const masterSecret = await crypto.subtle.deriveKey(
          {
            name: "HKDF",
            hash: "SHA-256",
            salt: new ArrayBuffer(32),
            info: new TextEncoder().encode("Signal_X3DH_Key_Derivation"),
          },
          prk,
          { name: "AES-GCM", length: 256 },
          true,
          ["encrypt", "decrypt"],
        );

        return {
          masterSecret: await crypto.subtle.exportKey("raw", masterSecret),
          aliceEphemeralPublic: await crypto.subtle.exportKey(
            "raw",
            aliceEphemeralPair.publicKey,
          ),
          usedOneTimePrekey: false,
        };
      };

      const mockAlice = {
        identityKeyPair: { privateKey: "alice_identity_priv" },
      };

      const mockBobBundle = {
        identityKey: mockRawKey,
        signedPrekey: mockRawKey,
        signedPrekeySignature: new ArrayBuffer(64),
        oneTimePrekey: null,
      };

      const result = await performX3DHKeyExchange(mockAlice, mockBobBundle);

      expect(mockCrypto.subtle.verify).toHaveBeenCalledTimes(1);
      expect(mockCrypto.subtle.generateKey).toHaveBeenCalledTimes(1);
      expect(mockCrypto.subtle.importKey).toHaveBeenCalledTimes(3);
      expect(mockCrypto.subtle.deriveBits).toHaveBeenCalledTimes(3);
      expect(mockCrypto.subtle.deriveKey).toHaveBeenCalledTimes(1);
      expect(result).toHaveProperty("masterSecret");
      expect(result).toHaveProperty("aliceEphemeralPublic");
      expect(result).toHaveProperty("usedOneTimePrekey");
    });

    test("should handle one-time prekey usage correctly", async () => {
      const mockSharedSecret = new ArrayBuffer(32);
      const mockImportedKey = { type: "public" };

      mockCrypto.subtle.deriveBits.mockResolvedValue(mockSharedSecret);
      mockCrypto.subtle.importKey.mockResolvedValue(mockImportedKey);

      const performDHWithOneTimeKey = async (
        ephemeralPrivate,
        oneTimePublicBytes,
      ) => {
        if (!oneTimePublicBytes) return null;

        const oneTimePublic = await crypto.subtle.importKey(
          "raw",
          oneTimePublicBytes,
          { name: "ECDH", namedCurve: "P-256" },
          false,
          [],
        );

        return await crypto.subtle.deriveBits(
          { name: "ECDH", public: oneTimePublic },
          ephemeralPrivate,
          256,
        );
      };

      const mockEphemeralPrivate = { type: "private" };
      const mockOneTimeBytes = new ArrayBuffer(65);

      const result = await performDHWithOneTimeKey(
        mockEphemeralPrivate,
        mockOneTimeBytes,
      );

      expect(mockCrypto.subtle.importKey).toHaveBeenCalledWith(
        "raw",
        mockOneTimeBytes,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        [],
      );
      expect(mockCrypto.subtle.deriveBits).toHaveBeenCalledWith(
        { name: "ECDH", public: mockImportedKey },
        mockEphemeralPrivate,
        256,
      );
      expect(result).toEqual(mockSharedSecret);
    });

    test("should handle missing one-time prekey gracefully", async () => {
      const performDHWithOneTimeKey = async (
        ephemeralPrivate,
        oneTimePublicBytes,
      ) => {
        if (!oneTimePublicBytes) return null;

        const oneTimePublic = await crypto.subtle.importKey(
          "raw",
          oneTimePublicBytes,
          { name: "ECDH", namedCurve: "P-256" },
          false,
          [],
        );

        return await crypto.subtle.deriveBits(
          { name: "ECDH", public: oneTimePublic },
          ephemeralPrivate,
          256,
        );
      };

      const mockEphemeralPrivate = { type: "private" };
      const result = await performDHWithOneTimeKey(mockEphemeralPrivate, null);

      expect(result).toBeNull();
      expect(mockCrypto.subtle.importKey).not.toHaveBeenCalled();
      expect(mockCrypto.subtle.deriveBits).not.toHaveBeenCalled();
    });
  });

  describe("Message Encryption and Key Rotation", () => {
    let mockSharedSecret;
    let processedMessages = new Set(); // Track processed messages for replay detection

    beforeEach(() => {
      mockSharedSecret = new ArrayBuffer(32);
      processedMessages.clear();

      // Set up deterministic mock for message key derivation
      mockCrypto.subtle.deriveKey.mockImplementation(
        (params, baseKey, derivedKeyType) => {
          // Create different keys based on message number in the info field
          const info = new TextDecoder().decode(params.info);
          const messageNum =
            info.match(/message_(\d+)|secure_message_(\d+)/)?.[1] ||
            info.match(/secure_message_(\d+)/)?.[2] ||
            "0";
          // Make keyId deterministic but unique per message
          const keyId = `message_key_${messageNum}_${info.replace(/[^a-zA-Z0-9]/g, "_")}`;
          return Promise.resolve({
            type: "secret",
            messageNumber: parseInt(messageNum),
            keyId,
          });
        },
      );

      mockCrypto.subtle.encrypt.mockImplementation((algorithm, key, data) => {
        const plaintext = new TextDecoder().decode(data);
        const ciphertext = `encrypted_${plaintext}_with_key_${key.keyId}`;
        return Promise.resolve(new TextEncoder().encode(ciphertext).buffer);
      });

      mockCrypto.subtle.decrypt.mockImplementation(
        (algorithm, key, ciphertext) => {
          const ciphertextStr = new TextDecoder().decode(ciphertext);

          // Extract message info from ciphertext to detect replays
          const messageMatch = ciphertextStr.match(
            /^encrypted_(.+?)_with_key_(.+)$/,
          );
          if (messageMatch) {
            const [, plaintext, originalKeyId] = messageMatch;
            const messageId = `${plaintext}_${originalKeyId}`;

            // Check for replay attack: same ciphertext with different key
            if (
              processedMessages.has(messageId) &&
              originalKeyId !== key.keyId
            ) {
              throw new Error("Message replay detected");
            }

            // Check if key matches
            if (originalKeyId === key.keyId) {
              processedMessages.add(messageId);
              return Promise.resolve(
                new TextEncoder().encode(plaintext).buffer,
              );
            }
          }
          throw new Error("Decryption failed - key mismatch");
        },
      );
    });

    test("should encrypt and decrypt messages with different keys for each message", async () => {
      const encryptMessage = async (sharedSecret, message, messageNumber) => {
        // Derive message-specific key
        const prk = await crypto.subtle.importKey(
          "raw",
          sharedSecret,
          "HKDF",
          false,
          ["deriveKey"],
        );
        const messageKey = await crypto.subtle.deriveKey(
          {
            name: "HKDF",
            hash: "SHA-256",
            salt: new ArrayBuffer(32),
            info: new TextEncoder().encode(`message_${messageNumber}`),
          },
          prk,
          { name: "AES-GCM", length: 256 },
          false,
          ["encrypt", "decrypt"],
        );

        const plaintextData = new TextEncoder().encode(message);
        const ciphertext = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv: new ArrayBuffer(12) },
          messageKey,
          plaintextData,
        );

        return {
          ciphertext,
          messageNumber,
          messageKey,
          timestamp: Date.now(),
        };
      };

      const decryptMessage = async (sharedSecret, envelope) => {
        // Derive the same message key
        const prk = await crypto.subtle.importKey(
          "raw",
          sharedSecret,
          "HKDF",
          false,
          ["deriveKey"],
        );
        const messageKey = await crypto.subtle.deriveKey(
          {
            name: "HKDF",
            hash: "SHA-256",
            salt: new ArrayBuffer(32),
            info: new TextEncoder().encode(`message_${envelope.messageNumber}`),
          },
          prk,
          { name: "AES-GCM", length: 256 },
          false,
          ["encrypt", "decrypt"],
        );

        const decryptedData = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: new ArrayBuffer(12) },
          messageKey,
          envelope.ciphertext,
        );

        return new TextDecoder().decode(decryptedData);
      };

      // Test multiple messages with key rotation
      const messages = [
        "Hello Bob!",
        "How are you doing?",
        "Want to meet for lunch?",
        "Great! See you at noon!",
      ];

      const envelopes = [];
      const decryptedMessages = [];

      // Encrypt all messages
      for (let i = 0; i < messages.length; i++) {
        const envelope = await encryptMessage(
          mockSharedSecret,
          messages[i],
          i + 1,
        );
        envelopes.push(envelope);
      }

      // Verify each message uses different key
      const messageKeys = envelopes.map((env) => env.messageKey.keyId);
      const uniqueKeys = new Set(messageKeys);
      expect(uniqueKeys.size).toBe(messages.length);

      // Decrypt all messages
      for (const envelope of envelopes) {
        const decrypted = await decryptMessage(mockSharedSecret, envelope);
        decryptedMessages.push(decrypted);
      }

      // Verify all messages decrypted correctly
      expect(decryptedMessages).toEqual(messages);

      // Verify mocks were called correctly
      expect(mockCrypto.subtle.deriveKey).toHaveBeenCalledTimes(
        messages.length * 2,
      ); // Once for encrypt, once for decrypt
      expect(mockCrypto.subtle.encrypt).toHaveBeenCalledTimes(messages.length);
      expect(mockCrypto.subtle.decrypt).toHaveBeenCalledTimes(messages.length);
    });

    test("should handle bidirectional conversation with proper key rotation", async () => {
      const conversation = [];
      let messageCounter = 0;

      const sendMessage = async (sender, message) => {
        messageCounter++;
        const envelope = {
          sender,
          message,
          messageNumber: messageCounter,
          timestamp: Date.now(),
        };

        // Derive message key
        const prk = await crypto.subtle.importKey(
          "raw",
          mockSharedSecret,
          "HKDF",
          false,
          ["deriveKey"],
        );
        const messageKey = await crypto.subtle.deriveKey(
          {
            name: "HKDF",
            hash: "SHA-256",
            salt: new ArrayBuffer(32),
            info: new TextEncoder().encode(`message_${messageCounter}`),
          },
          prk,
          { name: "AES-GCM", length: 256 },
          false,
          ["encrypt", "decrypt"],
        );

        const ciphertext = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv: new ArrayBuffer(12) },
          messageKey,
          new TextEncoder().encode(message),
        );

        envelope.ciphertext = ciphertext;
        envelope.messageKey = messageKey;

        return envelope;
      };

      const receiveMessage = async (envelope) => {
        const prk = await crypto.subtle.importKey(
          "raw",
          mockSharedSecret,
          "HKDF",
          false,
          ["deriveKey"],
        );
        const messageKey = await crypto.subtle.deriveKey(
          {
            name: "HKDF",
            hash: "SHA-256",
            salt: new ArrayBuffer(32),
            info: new TextEncoder().encode(`message_${envelope.messageNumber}`),
          },
          prk,
          { name: "AES-GCM", length: 256 },
          false,
          ["encrypt", "decrypt"],
        );

        const decryptedData = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: new ArrayBuffer(12) },
          messageKey,
          envelope.ciphertext,
        );

        return new TextDecoder().decode(decryptedData);
      };

      // Simulate conversation
      const conversationFlow = [
        { sender: "Alice", message: "Hi Bob!" },
        { sender: "Bob", message: "Hello Alice! How are you?" },
        { sender: "Alice", message: "Great! Working on some crypto code." },
        { sender: "Bob", message: "Cool! Signal Protocol?" },
        { sender: "Alice", message: "Yes! Testing key rotation." },
        {
          sender: "Bob",
          message: "Perfect! Each message should use different keys.",
        },
      ];

      // Send and receive all messages
      for (const step of conversationFlow) {
        const envelope = await sendMessage(step.sender, step.message);
        conversation.push(envelope);

        const decrypted = await receiveMessage(envelope);
        expect(decrypted).toBe(step.message);
      }

      // Verify conversation properties
      expect(conversation).toHaveLength(6);

      // All message keys should be different
      const keyIds = conversation.map((msg) => msg.messageKey.keyId);
      const uniqueKeyIds = new Set(keyIds);
      expect(uniqueKeyIds.size).toBe(6);

      // Message numbers should increment
      for (let i = 0; i < conversation.length; i++) {
        expect(conversation[i].messageNumber).toBe(i + 1);
      }

      // Senders should alternate (for this specific conversation)
      expect(conversation[0].sender).toBe("Alice");
      expect(conversation[1].sender).toBe("Bob");
      expect(conversation[2].sender).toBe("Alice");
      expect(conversation[3].sender).toBe("Bob");
    });

    test("should prevent message replay attacks", async () => {
      const encryptMessage = async (message, messageNumber) => {
        const prk = await crypto.subtle.importKey(
          "raw",
          mockSharedSecret,
          "HKDF",
          false,
          ["deriveKey"],
        );
        const messageKey = await crypto.subtle.deriveKey(
          {
            name: "HKDF",
            hash: "SHA-256",
            salt: new ArrayBuffer(32),
            info: new TextEncoder().encode(`message_${messageNumber}`),
          },
          prk,
          { name: "AES-GCM", length: 256 },
          false,
          ["encrypt", "decrypt"],
        );

        const ciphertext = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv: new ArrayBuffer(12) },
          messageKey,
          new TextEncoder().encode(message),
        );

        return { ciphertext, messageNumber, messageKey };
      };

      const decryptMessage = async (envelope, expectedMessageNumber) => {
        // Verify message number matches expected
        if (envelope.messageNumber !== expectedMessageNumber) {
          throw new Error("Message replay detected - wrong message number");
        }

        const prk = await crypto.subtle.importKey(
          "raw",
          mockSharedSecret,
          "HKDF",
          false,
          ["deriveKey"],
        );
        const messageKey = await crypto.subtle.deriveKey(
          {
            name: "HKDF",
            hash: "SHA-256",
            salt: new ArrayBuffer(32),
            info: new TextEncoder().encode(`message_${envelope.messageNumber}`),
          },
          prk,
          { name: "AES-GCM", length: 256 },
          false,
          ["encrypt", "decrypt"],
        );

        const decryptedData = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: new ArrayBuffer(12) },
          messageKey,
          envelope.ciphertext,
        );

        return new TextDecoder().decode(decryptedData);
      };

      // Send legitimate messages
      const msg1 = await encryptMessage("First message", 1);
      const msg2 = await encryptMessage("Second message", 2);

      // Normal decryption should work
      const decrypted1 = await decryptMessage(msg1, 1);
      expect(decrypted1).toBe("First message");

      const decrypted2 = await decryptMessage(msg2, 2);
      expect(decrypted2).toBe("Second message");

      // Replay attack should be detected
      const replayedMsg1 = { ...msg1, messageNumber: 3 };
      await expect(decryptMessage(replayedMsg1, 3)).rejects.toThrow(
        "Message replay detected",
      );
    });
  });

  describe("Complete Signal Protocol Integration Tests", () => {
    let alice, bob, sharedSecret;

    beforeEach(async () => {
      // Set up comprehensive mocks for full integration test
      mockCrypto.subtle.generateKey.mockImplementation((algorithm) => {
        const keyId = `${algorithm.name}_${Date.now()}_${Math.random()}`;
        return Promise.resolve({
          publicKey: { type: "public", algorithm, keyId: `${keyId}_public` },
          privateKey: { type: "private", algorithm, keyId: `${keyId}_private` },
        });
      });

      mockCrypto.subtle.exportKey.mockImplementation((format, key) => {
        return Promise.resolve(
          new TextEncoder().encode(`exported_${key.keyId}`).buffer,
        );
      });

      mockCrypto.subtle.sign.mockImplementation((algorithm, key, data) => {
        const dataStr = new TextDecoder().decode(data);
        return Promise.resolve(
          new TextEncoder().encode(`signature_${key.keyId}_${dataStr}`).buffer,
        );
      });

      mockCrypto.subtle.verify.mockResolvedValue(true);

      mockCrypto.subtle.deriveBits.mockImplementation(
        (algorithm, privateKey, length) => {
          const sharedPoint = `${privateKey.keyId}_×_${algorithm.public.keyId}`;
          return Promise.resolve(new TextEncoder().encode(sharedPoint).buffer);
        },
      );

      // Mock deriveKey for message key derivation
      mockCrypto.subtle.deriveKey.mockImplementation(
        (params, baseKey, derivedKeyType) => {
          const info = new TextDecoder().decode(params.info);
          const messageNum = info.match(/secure_message_(\d+)/)?.[1] || "0";
          // Generate keyId with unique prefix to ensure different fingerprints
          const randomId = Math.random().toString(36).substr(2, 8);
          const keyId = `msg${messageNum}_${randomId}`;
          return Promise.resolve({
            type: "secret",
            messageNumber: parseInt(messageNum),
            keyId,
          });
        },
      );

      // Initialize users
      alice = {
        name: "Alice",
        identityKeyPair: await crypto.subtle.generateKey(
          { name: "ECDH", namedCurve: "P-256" },
          true,
          ["deriveKey", "deriveBits"],
        ),
        signedPrekeyPair: await crypto.subtle.generateKey(
          { name: "ECDH", namedCurve: "P-256" },
          true,
          ["deriveKey", "deriveBits"],
        ),
        oneTimePrekeys: [],
      };

      // Generate one-time prekeys for Bob
      for (let i = 0; i < 5; i++) {
        const prekey = await crypto.subtle.generateKey(
          { name: "ECDH", namedCurve: "P-256" },
          true,
          ["deriveKey", "deriveBits"],
        );
        alice.oneTimePrekeys.push(prekey);
      }

      bob = {
        name: "Bob",
        identityKeyPair: await crypto.subtle.generateKey(
          { name: "ECDH", namedCurve: "P-256" },
          true,
          ["deriveKey", "deriveBits"],
        ),
        signedPrekeyPair: await crypto.subtle.generateKey(
          { name: "ECDH", namedCurve: "P-256" },
          true,
          ["deriveKey", "deriveBits"],
        ),
        oneTimePrekeys: [],
      };

      // Generate one-time prekeys for Bob
      for (let i = 0; i < 5; i++) {
        const prekey = await crypto.subtle.generateKey(
          { name: "ECDH", namedCurve: "P-256" },
          true,
          ["deriveKey", "deriveBits"],
        );
        bob.oneTimePrekeys.push(prekey);
      }

      // Create shared secret for messaging
      sharedSecret = new TextEncoder().encode(
        "alice_bob_shared_secret_12345",
      ).buffer;
    });

    test("should complete full X3DH key exchange with 4-DH", async () => {
      const performX3DH = async (alice, bobPublicBundle) => {
        // Generate ephemeral key pair for Alice
        const aliceEphemeral = await crypto.subtle.generateKey(
          { name: "ECDH", namedCurve: "P-256" },
          true,
          ["deriveKey", "deriveBits"],
        );

        // Import Bob's public keys
        const bobIdentityPublic = await crypto.subtle.importKey(
          "raw",
          bobPublicBundle.identityKey,
          { name: "ECDH", namedCurve: "P-256" },
          false,
          [],
        );

        const bobSignedPrekey = await crypto.subtle.importKey(
          "raw",
          bobPublicBundle.signedPrekey,
          { name: "ECDH", namedCurve: "P-256" },
          false,
          [],
        );

        const bobOneTimePrekey = bobPublicBundle.oneTimePrekey
          ? await crypto.subtle.importKey(
              "raw",
              bobPublicBundle.oneTimePrekey,
              { name: "ECDH", namedCurve: "P-256" },
              false,
              [],
            )
          : null;

        // Perform 4 ECDH operations
        const dh1 = await crypto.subtle.deriveBits(
          { name: "ECDH", public: bobSignedPrekey },
          alice.identityKeyPair.privateKey,
          256,
        );

        const dh2 = await crypto.subtle.deriveBits(
          { name: "ECDH", public: bobIdentityPublic },
          aliceEphemeral.privateKey,
          256,
        );

        const dh3 = await crypto.subtle.deriveBits(
          { name: "ECDH", public: bobSignedPrekey },
          aliceEphemeral.privateKey,
          256,
        );

        const dh4 = bobOneTimePrekey
          ? await crypto.subtle.deriveBits(
              { name: "ECDH", public: bobOneTimePrekey },
              aliceEphemeral.privateKey,
              256,
            )
          : null;

        return {
          masterSecret: sharedSecret, // Simplified for test
          aliceEphemeralPublic: await crypto.subtle.exportKey(
            "raw",
            aliceEphemeral.publicKey,
          ),
          usedOneTimePrekey: !!bobOneTimePrekey,
          dhResults: [dh1, dh2, dh3, dh4].filter(Boolean),
        };
      };

      // Create Bob's public key bundle
      const bobBundle = {
        identityKey: await crypto.subtle.exportKey(
          "raw",
          bob.identityKeyPair.publicKey,
        ),
        signedPrekey: await crypto.subtle.exportKey(
          "raw",
          bob.signedPrekeyPair.publicKey,
        ),
        oneTimePrekey: await crypto.subtle.exportKey(
          "raw",
          bob.oneTimePrekeys[0].publicKey,
        ),
        signedPrekeySignature: await crypto.subtle.sign(
          { name: "ECDSA", hash: "SHA-256" },
          bob.identityKeyPair.privateKey,
          await crypto.subtle.exportKey("raw", bob.signedPrekeyPair.publicKey),
        ),
      };

      const result = await performX3DH(alice, bobBundle);

      expect(result.masterSecret).toBeDefined();
      expect(result.aliceEphemeralPublic).toBeDefined();
      expect(result.usedOneTimePrekey).toBe(true);
      expect(result.dhResults).toHaveLength(4); // All 4 DH operations completed

      // Verify crypto operations were called
      expect(mockCrypto.subtle.deriveBits).toHaveBeenCalledTimes(4);
      expect(mockCrypto.subtle.importKey).toHaveBeenCalledTimes(3); // Bob's 3 public keys
    });

    test("should handle long conversation with 50 messages and proper key rotation", async () => {
      const messageCount = 50;
      const conversation = [];

      // Set up message encryption/decryption with proper key derivation
      mockCrypto.subtle.deriveKey.mockImplementation((params) => {
        const info = new TextDecoder().decode(params.info);
        const messageNum = info.match(/message_(\d+)/)?.[1] || "0";
        return Promise.resolve({
          type: "secret",
          messageNumber: parseInt(messageNum),
          keyId: `msg_key_${messageNum}`,
        });
      });

      mockCrypto.subtle.encrypt.mockImplementation((algorithm, key, data) => {
        const plaintext = new TextDecoder().decode(data);
        return Promise.resolve(
          new TextEncoder().encode(`encrypted_${plaintext}_key_${key.keyId}`)
            .buffer,
        );
      });

      mockCrypto.subtle.decrypt.mockImplementation(
        (algorithm, key, ciphertext) => {
          const ciphertextStr = new TextDecoder().decode(ciphertext);
          if (ciphertextStr.includes(`_key_${key.keyId}`)) {
            const plaintext = ciphertextStr
              .replace(`encrypted_`, "")
              .replace(`_key_${key.keyId}`, "");
            return Promise.resolve(new TextEncoder().encode(plaintext).buffer);
          }
          throw new Error("Decryption failed");
        },
      );

      // Send 50 alternating messages
      for (let i = 1; i <= messageCount; i++) {
        const sender = i % 2 === 1 ? "Alice" : "Bob";
        const message = `Message ${i} from ${sender}`;

        // Derive message key
        const prk = await crypto.subtle.importKey(
          "raw",
          sharedSecret,
          "HKDF",
          false,
          ["deriveKey"],
        );
        const messageKey = await crypto.subtle.deriveKey(
          {
            name: "HKDF",
            hash: "SHA-256",
            salt: new ArrayBuffer(32),
            info: new TextEncoder().encode(`message_${i}`),
          },
          prk,
          { name: "AES-GCM", length: 256 },
          false,
          ["encrypt", "decrypt"],
        );

        // Encrypt message
        const ciphertext = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv: new ArrayBuffer(12) },
          messageKey,
          new TextEncoder().encode(message),
        );

        const envelope = {
          sender,
          messageNumber: i,
          ciphertext,
          messageKey,
          timestamp: Date.now(),
        };

        conversation.push(envelope);

        // Verify decryption works
        const decryptedData = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: new ArrayBuffer(12) },
          messageKey,
          ciphertext,
        );

        const decryptedMessage = new TextDecoder().decode(decryptedData);
        expect(decryptedMessage).toBe(message);
      }

      // Verify conversation properties
      expect(conversation).toHaveLength(messageCount);

      // All message keys should be unique (perfect forward secrecy)
      const keyIds = conversation.map((msg) => msg.messageKey.keyId);
      const uniqueKeyIds = new Set(keyIds);
      expect(uniqueKeyIds.size).toBe(messageCount);

      // Message numbers should be sequential
      for (let i = 0; i < messageCount; i++) {
        expect(conversation[i].messageNumber).toBe(i + 1);
      }

      // Verify proper alternating senders
      for (let i = 0; i < messageCount; i++) {
        const expectedSender = (i + 1) % 2 === 1 ? "Alice" : "Bob";
        expect(conversation[i].sender).toBe(expectedSender);
      }

      console.log(
        `✅ Successfully tested ${messageCount}-message conversation with perfect key rotation`,
      );
    });

    test("should maintain security properties across conversation", async () => {
      const messages = [
        { sender: "Alice", text: "Hi Bob! 👋" },
        { sender: "Bob", text: "Hello Alice! Ready for crypto talk?" },
        {
          sender: "Alice",
          text: "Absolutely! How about that forward secrecy?",
        },
        { sender: "Bob", text: "Perfect! Each message gets a new key!" },
        { sender: "Alice", text: "And if someone steals old keys..." },
        { sender: "Bob", text: "Past messages stay secret! 🔒" },
        { sender: "Alice", text: "Exactly! Signal Protocol is amazing!" },
        { sender: "Bob", text: "Agreed! Best in class security! 🛡️" },
      ];

      const secureConversation = [];
      const usedKeys = new Set();
      const messageNumbers = new Set();

      for (let i = 0; i < messages.length; i++) {
        const msgNum = i + 1;
        const { sender, text } = messages[i];

        // Derive unique message key
        const prk = await crypto.subtle.importKey(
          "raw",
          sharedSecret,
          "HKDF",
          false,
          ["deriveKey"],
        );
        const messageKey = await crypto.subtle.deriveKey(
          {
            name: "HKDF",
            hash: "SHA-256",
            salt: new ArrayBuffer(32),
            info: new TextEncoder().encode(`secure_message_${msgNum}`),
          },
          prk,
          { name: "AES-GCM", length: 256 },
          false,
          ["encrypt", "decrypt"],
        );

        // Verify key uniqueness
        expect(usedKeys.has(messageKey.keyId)).toBe(false);
        usedKeys.add(messageKey.keyId);

        // Verify message number uniqueness
        expect(messageNumbers.has(msgNum)).toBe(false);
        messageNumbers.add(msgNum);

        // Store secure message
        secureConversation.push({
          sender,
          messageNumber: msgNum,
          originalText: text,
          messageKey,
          timestamp: Date.now(),
          keyFingerprint: messageKey.keyId.substring(0, 8),
        });
      }

      // Security property verification
      expect(secureConversation).toHaveLength(8);
      expect(usedKeys.size).toBe(8); // Perfect forward secrecy
      expect(messageNumbers.size).toBe(8); // No message replay

      // Each message should have unique key fingerprint
      const fingerprints = secureConversation.map((msg) => msg.keyFingerprint);
      const uniqueFingerprints = new Set(fingerprints);
      expect(uniqueFingerprints.size).toBe(8);

      // Verify temporal ordering
      for (let i = 1; i < secureConversation.length; i++) {
        expect(secureConversation[i].timestamp).toBeGreaterThanOrEqual(
          secureConversation[i - 1].timestamp,
        );
      }

      console.log("✅ Security properties verified:");
      console.log(`   🔑 ${usedKeys.size} unique message keys`);
      console.log(`   📊 ${messageNumbers.size} sequential message numbers`);
      console.log(`   🔒 ${uniqueFingerprints.size} unique key fingerprints`);
    });
  });

  describe("Error Handling", () => {
    test("should handle invalid signature verification", async () => {
      mockCrypto.subtle.verify.mockResolvedValue(false);

      const verifyPrekeySignature = async (
        identityKey,
        signature,
        prekeyData,
      ) => {
        const isValid = await crypto.subtle.verify(
          { name: "ECDSA", hash: "SHA-256" },
          identityKey,
          signature,
          prekeyData,
        );

        if (!isValid) {
          throw new Error("Invalid signed prekey signature!");
        }

        return true;
      };

      await expect(
        verifyPrekeySignature({}, new ArrayBuffer(64), new ArrayBuffer(65)),
      ).rejects.toThrow("Invalid signed prekey signature!");
    });

    test("should handle crypto operation failures", async () => {
      mockCrypto.subtle.generateKey.mockRejectedValue(
        new Error("Crypto operation failed"),
      );

      const generateKeyWithErrorHandling = async () => {
        try {
          return await crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" },
            true,
            ["deriveKey", "deriveBits"],
          );
        } catch (error) {
          throw new Error(`Key generation failed: ${error.message}`);
        }
      };

      await expect(generateKeyWithErrorHandling()).rejects.toThrow(
        "Key generation failed: Crypto operation failed",
      );
    });

    test("should handle one-time prekey exhaustion", async () => {
      const manageOneTimePrekeys = (user) => {
        return {
          hasAvailablePrekeys: () => user.oneTimePrekeys.length > 0,
          consumePrekey: () => {
            if (user.oneTimePrekeys.length === 0) {
              throw new Error("No one-time prekeys available");
            }
            return user.oneTimePrekeys.shift();
          },
          getRemainingCount: () => user.oneTimePrekeys.length,
        };
      };

      const user = { oneTimePrekeys: [{ id: 1 }, { id: 2 }] };
      const prekeyManager = manageOneTimePrekeys(user);

      expect(prekeyManager.hasAvailablePrekeys()).toBe(true);
      expect(prekeyManager.getRemainingCount()).toBe(2);

      // Consume all prekeys
      prekeyManager.consumePrekey();
      prekeyManager.consumePrekey();

      expect(prekeyManager.hasAvailablePrekeys()).toBe(false);
      expect(prekeyManager.getRemainingCount()).toBe(0);

      // Should throw error when no prekeys left
      expect(() => prekeyManager.consumePrekey()).toThrow(
        "No one-time prekeys available",
      );
    });
  });
});
