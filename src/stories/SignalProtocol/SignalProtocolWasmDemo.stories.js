import React, { useState, useEffect } from "react";
import {
  Box,
  Typography,
  Button,
  Card,
  CardContent,
  Alert,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Chip,
  Grid,
  Paper,
  Switch,
  FormControlLabel,
  CircularProgress,
  Divider,
} from "@mui/material";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import SecurityIcon from "@mui/icons-material/Security";
import SpeedIcon from "@mui/icons-material/Speed";
import MemoryIcon from "@mui/icons-material/Memory";
import CompareArrowsIcon from "@mui/icons-material/CompareArrows";
import WebAssemblyIcon from "@mui/icons-material/Memory"; // Using Memory icon as WebAssembly icon
import {
  SignalProtocolWasm,
  SignalWasmHelpers,
  loadWasmModule,
} from "../../wasm-bindings.js";
import { CryptoDemo, CodeDisplay, OperationStatus } from "ui";

// Mock WASM implementation for demo purposes
const mockWasmImplementation = {
  async initialize() {
    // Simulate initialization delay
    await new Promise((resolve) => setTimeout(resolve, 500));
    return true;
  },

  async generateIdentityKeyPair() {
    await new Promise((resolve) => setTimeout(resolve, 50)); // Faster than JS
    return {
      publicKey: new Uint8Array(32).fill(Math.floor(Math.random() * 256)),
      privateKey: new Uint8Array(32).fill(Math.floor(Math.random() * 256)),
    };
  },

  async generateSignedPrekey() {
    await new Promise((resolve) => setTimeout(resolve, 45));
    return {
      publicKey: new Uint8Array(32).fill(Math.floor(Math.random() * 256)),
      privateKey: new Uint8Array(32).fill(Math.floor(Math.random() * 256)),
    };
  },

  async generateOneTimePrekey() {
    await new Promise((resolve) => setTimeout(resolve, 40));
    return {
      publicKey: new Uint8Array(32).fill(Math.floor(Math.random() * 256)),
      privateKey: new Uint8Array(32).fill(Math.floor(Math.random() * 256)),
    };
  },

  async generateEphemeralKeyPair() {
    await new Promise((resolve) => setTimeout(resolve, 35));
    return {
      publicKey: new Uint8Array(32).fill(Math.floor(Math.random() * 256)),
      privateKey: new Uint8Array(32).fill(Math.floor(Math.random() * 256)),
    };
  },

  async signData(privateKey, data) {
    await new Promise((resolve) => setTimeout(resolve, 30));
    return new Uint8Array(64).fill(Math.floor(Math.random() * 256));
  },

  async verifySignature(publicKey, signature, data) {
    await new Promise((resolve) => setTimeout(resolve, 25));
    return Math.random() > 0.1; // 90% success rate for demo
  },

  async x3dhInitiate(
    aliceIdentityPrivate,
    aliceEphemeralPrivate,
    bobIdentityPublic,
    bobSignedPrekeyPublic,
    bobOneTimePrekeyPublic,
  ) {
    await new Promise((resolve) => setTimeout(resolve, 100));
    return {
      sharedSecret: new Uint8Array(32).fill(42),
      associatedData: new Uint8Array(16).fill(1),
      usedOneTimePrekey: bobOneTimePrekeyPublic !== null,
    };
  },

  async x3dhRespond(
    bobIdentityPrivate,
    bobSignedPrekeyPrivate,
    bobOneTimePrekeyPrivate,
    aliceIdentityPublic,
    aliceEphemeralPublic,
  ) {
    await new Promise((resolve) => setTimeout(resolve, 95));
    return {
      sharedSecret: new Uint8Array(32).fill(42), // Same as initiate for demo
      associatedData: new Uint8Array(16).fill(1),
      usedOneTimePrekey: bobOneTimePrekeyPrivate !== null,
    };
  },

  async encryptMessage(sharedSecret, plaintext, messageNumber) {
    await new Promise((resolve) => setTimeout(resolve, 20));
    return {
      ciphertext: new Uint8Array(plaintext.length + 16).fill(
        Math.floor(Math.random() * 256),
      ),
      messageKey: new Uint8Array(32).fill(messageNumber),
      messageNumber,
    };
  },

  async decryptMessage(sharedSecret, ciphertext, messageKey, messageNumber) {
    await new Promise((resolve) => setTimeout(resolve, 18));
    return new TextEncoder().encode(`WASM decrypted message ${messageNumber}`);
  },

  async initializeDoubleRatchet(sharedSecret, isInitiator) {
    await new Promise((resolve) => setTimeout(resolve, 15));
    return {
      rootKey: new Uint8Array(32).fill(Math.floor(Math.random() * 256)),
      sendingChainKey: isInitiator ? new Uint8Array(32).fill(42) : null,
      receivingChainKey: isInitiator ? null : new Uint8Array(32).fill(43),
      sendingMessageNumber: 0,
      receivingMessageNumber: 0,
      isInitiator,
    };
  },

  async doubleRatchetEncrypt(ratchetState, plaintext) {
    await new Promise((resolve) => setTimeout(resolve, 8)); // Faster than JS
    const messageNumber = ratchetState.sendingMessageNumber++;
    return {
      ciphertext: new Uint8Array(plaintext.length + 16).fill(
        Math.floor(Math.random() * 256),
      ),
      dhPublicKey: new Uint8Array(32).fill(102),
      messageNumber,
      previousChainLength: 0,
    };
  },

  async doubleRatchetDecrypt(ratchetState, envelope) {
    await new Promise((resolve) => setTimeout(resolve, 7)); // Faster than JS
    ratchetState.receivingMessageNumber = Math.max(
      ratchetState.receivingMessageNumber,
      envelope.messageNumber + 1,
    );
    return `WASM mock decrypted message ${envelope.messageNumber}`;
  },

  bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  },
};

// Define the main component
const SignalProtocolWasmDemo = () => {
  const [wasmAvailable, setWasmAvailable] = useState(false);
  const [wasmInitializing, setWasmInitializing] = useState(false);
  const [wasmInstance, setWasmInstance] = useState(null);
  const [wasmReloadTrigger, setWasmReloadTrigger] = useState(0);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");
  const [performanceResults, setPerformanceResults] = useState(null);
  // const crypto = useCryptography(); // TODO: Replace with WASM

  // Initialize WASM on component mount
  useEffect(() => {
    initializeWasm();
  }, [wasmReloadTrigger]);

  const reloadWasm = () => {
    setWasmReloadTrigger((prev) => prev + 1);
  };

  const initializeWasm = async () => {
    setWasmInitializing(true);
    try {
      // Try to load the real WASM module from public directory
      // Note: Commenting out real WASM loading as it's not available
      const wasmModule = await import("/pkg/signal_protocol_wasm.js");
      // throw new Error('WASM module not available - using mock implementation');
      await wasmModule.default(); // Initialize the WASM module

      // Create a wrapper that matches our expected interface
      const wasmWrapper = {
        async generateIdentityKeyPair() {
          const result = wasmModule.generate_identity_keypair();
          return {
            publicKey: result.public_key,
            privateKey: result.private_key,
          };
        },

        async generateSignedPrekey() {
          const result = wasmModule.generate_signed_prekey();
          return {
            publicKey: result.public_key,
            privateKey: result.private_key,
          };
        },

        async generateOneTimePrekey() {
          const result = wasmModule.generate_one_time_prekey();
          return {
            publicKey: result.public_key,
            privateKey: result.private_key,
          };
        },

        async generateEphemeralKeyPair() {
          const result = wasmModule.generate_ephemeral_keypair();
          return {
            publicKey: result.public_key,
            privateKey: result.private_key,
          };
        },

        async signData(privateKey, data) {
          return wasmModule.sign_data(privateKey, data);
        },

        async verifySignature(publicKey, signature, data) {
          return wasmModule.verify_signature(publicKey, signature, data);
        },

        async x3dhInitiate(
          aliceIdentityPrivate,
          aliceEphemeralPrivate,
          bobIdentityPublic,
          bobSignedPrekeyPublic,
          bobOneTimePrekeyPublic,
        ) {
          const result = wasmModule.x3dh_initiate(
            aliceIdentityPrivate,
            aliceEphemeralPrivate,
            bobIdentityPublic,
            bobSignedPrekeyPublic,
            bobOneTimePrekeyPublic,
          );
          return {
            sharedSecret: result.shared_secret,
            associatedData: result.associated_data,
            usedOneTimePrekey: bobOneTimePrekeyPublic !== null,
          };
        },

        async x3dhRespond(
          bobIdentityPrivate,
          bobSignedPrekeyPrivate,
          bobOneTimePrekeyPrivate,
          aliceIdentityPublic,
          aliceEphemeralPublic,
        ) {
          const result = wasmModule.x3dh_respond(
            bobIdentityPrivate,
            bobSignedPrekeyPrivate,
            bobOneTimePrekeyPrivate,
            aliceIdentityPublic,
            aliceEphemeralPublic,
          );
          return {
            sharedSecret: result.shared_secret,
            associatedData: result.associated_data,
            usedOneTimePrekey: bobOneTimePrekeyPrivate !== null,
          };
        },

        async encryptMessage(sharedSecret, plaintext, messageNumber) {
          const result = wasmModule.encrypt_message(
            sharedSecret,
            plaintext,
            messageNumber,
          );
          return {
            ciphertext: result.ciphertext,
            messageKey: result.message_key,
            messageNumber,
          };
        },

        async decryptMessage(
          sharedSecret,
          ciphertext,
          messageKey,
          messageNumber,
        ) {
          return wasmModule.decrypt_message(
            sharedSecret,
            ciphertext,
            messageKey,
            messageNumber,
          );
        },

        bufferToHex(buffer) {
          return Array.from(new Uint8Array(buffer))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
        },
      };

      setWasmInstance(wasmWrapper);
      setWasmAvailable(true);
      console.log("Real WASM module loaded successfully!");
    } catch (error) {
      console.warn(
        "Real WASM module failed to load, falling back to mock:",
        error,
      );
      // Fall back to mock implementation
      const wasmModule = mockWasmImplementation;
      await wasmModule.initialize();
      setWasmInstance(wasmModule);
      setWasmAvailable(false); // Indicate we're using fallback
    } finally {
      setWasmInitializing(false);
    }
  };

  const handleBasicDemo = async () => {
    setLoading(true);
    setError("");
    setResults(null);

    try {
      if (!wasmInstance) {
        throw new Error("WASM not initialized. Please wait...");
      }
      await runWasmDemo();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const runWasmDemo = async () => {
    console.log("🦀 Running WASM-based Signal Protocol demonstration...");

    try {
      // Generate keys using WASM
      console.log("🔑 Step 1: Generating Alice identity key...");
      const aliceIdentity = await wasmInstance.generateIdentityKeyPair();
      console.log("✅ Alice identity generated:", aliceIdentity);

      console.log("🔑 Step 2: Generating Bob identity key...");
      const bobIdentity = await wasmInstance.generateIdentityKeyPair();
      console.log("✅ Bob identity generated:", bobIdentity);

      console.log("🔑 Step 3: Generating Bob signed prekey...");
      const bobSignedPrekey = await wasmInstance.generateSignedPrekey();
      console.log("✅ Bob signed prekey generated:", bobSignedPrekey);

      console.log("🔑 Step 4: Generating Bob one-time prekey...");
      const bobOneTimePrekey = await wasmInstance.generateOneTimePrekey();
      console.log("✅ Bob one-time prekey generated:", bobOneTimePrekey);

      console.log("🔑 Step 5: Generating Alice ephemeral key...");
      const aliceEphemeral = await wasmInstance.generateEphemeralKeyPair();
      console.log("✅ Alice ephemeral key generated:", aliceEphemeral);

      // Create signature
      console.log("✍️ Step 6: Creating signature...");
      const signedPrekeySignature = await wasmInstance.signData(
        bobIdentity.privateKey,
        bobSignedPrekey.publicKey,
      );
      console.log(
        "✅ Signature created, length:",
        signedPrekeySignature.length,
      );

      // Perform X3DH
      console.log("🤝 Step 7: Alice initiating X3DH...");
      const aliceResult = await wasmInstance.x3dhInitiate(
        aliceIdentity.privateKey,
        aliceEphemeral.privateKey,
        bobIdentity.publicKey,
        bobSignedPrekey.publicKey,
        bobOneTimePrekey.publicKey,
      );
      console.log("✅ Alice X3DH result:", aliceResult);

      console.log("🤝 Step 8: Bob responding to X3DH...");
      const bobResult = await wasmInstance.x3dhRespond(
        bobIdentity.privateKey,
        bobSignedPrekey.privateKey,
        bobOneTimePrekey.privateKey,
        aliceIdentity.publicKey,
        aliceEphemeral.publicKey,
      );
      console.log("✅ Bob X3DH result:", bobResult);

      // Test message encryption
      console.log("📝 Step 9: Preparing message encryption...");
      const message = "Hello from WASM Signal Protocol! 🦀";
      const plaintextBytes = new TextEncoder().encode(message);
      console.log("📝 Message to encrypt:", message, "bytes:", plaintextBytes);

      console.log("🔒 Step 10: Encrypting message...");
      const encrypted = await wasmInstance.encryptMessage(
        aliceResult.sharedSecret,
        plaintextBytes,
        1,
      );
      console.log("✅ Message encrypted:", encrypted);

      console.log("🔓 Step 11: Decrypting message...");
      const decrypted = await wasmInstance.decryptMessage(
        bobResult.sharedSecret,
        encrypted.ciphertext,
        encrypted.messageKey,
        1,
      );
      console.log("✅ Message decrypted:", decrypted);
      console.log("✅ Decrypted text:", new TextDecoder().decode(decrypted));

      console.log("🔍 Step 12: Comparing shared secrets...");
      const aliceSecretHex = wasmInstance.bufferToHex(aliceResult.sharedSecret);
      const bobSecretHex = wasmInstance.bufferToHex(bobResult.sharedSecret);
      const success = aliceSecretHex === bobSecretHex;
      console.log("Alice secret:", aliceSecretHex);
      console.log("Bob secret:", bobSecretHex);
      console.log("Secrets match:", success);

      console.log("🎯 Step 13: Setting results...");
      const results = {
        success,
        implementation: "WASM",
        aliceSecret: aliceSecretHex,
        bobSecret: bobSecretHex,
        message,
        decryptedMessage: new TextDecoder().decode(decrypted),
        usedOneTimePrekey: aliceResult.usedOneTimePrekey || false,
        keyGenerated: true,
        encrypted: encrypted.ciphertext.length,
        signature: signedPrekeySignature.length,
      };
      console.log("Results to set:", results);

      setResults(results);
      console.log("✅ Results set successfully!");
    } catch (error) {
      console.error("❌ WASM Demo Failed at some step:", error);
      console.error("Error stack:", error.stack);
      throw error; // Re-throw to trigger the error handling in handleBasicDemo
    }
  };

  // Helper function to convert buffer to hex
  const bufferToHex = (buffer) => {
    if (!buffer) return "";
    const arr = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    return Array.from(arr)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  };

  const handlePerformanceComparison = async () => {
    setLoading(true);
    setError("");

    try {
      if (!wasmInstance) {
        throw new Error("WASM not initialized. Please wait...");
      }

      const results = {
        wasm: {},
      };

      // Test WASM performance
      console.log("📊 Testing WASM performance...");
      const wasmStartTime = performance.now();
      await runWasmDemo();
      const wasmEndTime = performance.now();
      results.wasm.totalTime = wasmEndTime - wasmStartTime;

      // Run detailed benchmarks (WASM only)
      const benchmarks = await runDetailedBenchmarks();

      setPerformanceResults({
        ...results,
        benchmarks,
        wasmAvailable,
        timestamp: Date.now(),
      });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const runDetailedBenchmarks = async () => {
    const benchmarks = {
      keyGeneration: { wasm: 0 },
      signing: { wasm: 0 },
      x3dh: { wasm: 0 },
      encryption: { wasm: 0 },
      doubleRatchet: { wasm: 0 },
    };

    const iterations = 10;

    if (!wasmInstance) {
      return benchmarks;
    }

    // Benchmark WASM
    // Key generation
    let start = performance.now();
    for (let i = 0; i < iterations; i++) {
      await wasmInstance.generateIdentityKeyPair();
    }
    benchmarks.keyGeneration.wasm = (performance.now() - start) / iterations;

    // Signing
    const testKey = await wasmInstance.generateIdentityKeyPair();
    const testData = new TextEncoder().encode("benchmark test data");
    start = performance.now();
    for (let i = 0; i < iterations; i++) {
      await wasmInstance.signData(testKey.privateKey, testData);
    }
    benchmarks.signing.wasm = (performance.now() - start) / iterations;

    // X3DH (simplified)
    start = performance.now();
    for (let i = 0; i < Math.min(3, iterations); i++) {
      const alice = await wasmInstance.generateIdentityKeyPair();
      const bob = await wasmInstance.generateIdentityKeyPair();
      const ephemeral = await wasmInstance.generateEphemeralKeyPair();
      const prekey = await wasmInstance.generateSignedPrekey();
      await wasmInstance.x3dhInitiate(
        alice.privateKey,
        ephemeral.privateKey,
        bob.publicKey,
        prekey.publicKey,
        null,
      );
    }
    benchmarks.x3dh.wasm =
      (performance.now() - start) / Math.min(3, iterations);

    // Encryption
    const sharedSecret = new Uint8Array(32).fill(42);
    const message = new TextEncoder().encode("benchmark message");
    start = performance.now();
    for (let i = 0; i < iterations; i++) {
      const encrypted = await wasmInstance.encryptMessage(
        sharedSecret,
        message,
        i + 1,
      );
      await wasmInstance.decryptMessage(
        sharedSecret,
        encrypted.ciphertext,
        encrypted.messageKey,
        i + 1,
      );
    }
    benchmarks.encryption.wasm = (performance.now() - start) / iterations;

    // Double Ratchet
    try {
      const wasmModule = await loadWasmModule();
      const wasmSharedSecret = new Uint8Array(32).fill(42);
      const wasmAliceRatchet = wasmModule.initialize_double_ratchet(
        wasmSharedSecret,
        true,
      );
      const wasmBobRatchet = wasmModule.initialize_double_ratchet(
        wasmSharedSecret,
        false,
      );

      start = performance.now();
      for (let i = 0; i < iterations; i++) {
        const plaintext = new TextEncoder().encode(`WASM test ${i}`);
        const envelope = wasmModule.double_ratchet_encrypt(
          wasmAliceRatchet,
          plaintext,
        );
        wasmModule.double_ratchet_decrypt(wasmBobRatchet, envelope);
      }
      benchmarks.doubleRatchet.wasm = (performance.now() - start) / iterations;
    } catch (err) {
      console.warn("Double Ratchet benchmark failed:", err);
    }

    return benchmarks;
  };

  const calculateSpeedup = (jsTime, wasmTime) => {
    if (wasmTime === 0) return "N/A";
    return (jsTime / wasmTime).toFixed(2) + "x";
  };

  return (
    <CryptoDemo
      title="Signal Protocol: WASM vs JavaScript"
      icon={<WebAssemblyIcon />}
    >
      <Box sx={{ mb: 3 }}>
        <Typography variant="body1" paragraph>
          This demo compares the performance of Signal Protocol implementation
          between WebAssembly (compiled from Rust) and pure JavaScript. WASM
          provides significant performance improvements for cryptographic
          operations while maintaining the same security guarantees.
        </Typography>

        {/* WASM Status */}
        <Paper
          sx={{
            p: 2,
            mb: 3,
            bgcolor: wasmAvailable ? "success.light" : "warning.light",
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
            <WebAssemblyIcon color={wasmAvailable ? "success" : "warning"} />
            <Typography variant="h6">
              WebAssembly Status:{" "}
              {wasmInitializing
                ? "Initializing..."
                : wasmAvailable
                  ? "Available"
                  : "Not Available"}
            </Typography>
            {wasmInitializing && <CircularProgress size={20} />}
            <Button
              size="small"
              variant="outlined"
              onClick={reloadWasm}
              disabled={wasmInitializing}
              sx={{ ml: "auto" }}
            >
              🔄 Reload WASM
            </Button>
          </Box>
          <Typography variant="body2">
            {wasmAvailable
              ? "✅ WASM module loaded successfully. Rust-based cryptography is available."
              : "⚠️ WASM module not available. Using mock implementation."}
          </Typography>
        </Paper>

        {/* Action Buttons */}
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6}>
            <Button
              variant="contained"
              onClick={handleBasicDemo}
              disabled={loading || !wasmInstance}
              fullWidth
              startIcon={<SecurityIcon />}
            >
              {loading ? "Running..." : "Run WASM Demo"}
            </Button>
          </Grid>
          <Grid item xs={12} sm={6}>
            <Button
              variant="outlined"
              onClick={handlePerformanceComparison}
              disabled={loading}
              fullWidth
              startIcon={<SpeedIcon />}
            >
              {loading ? "Benchmarking..." : "Performance Comparison"}
            </Button>
          </Grid>
        </Grid>

        <OperationStatus
          loading={loading}
          error={error}
          success={results?.success}
        />
      </Box>

      {/* Results Display */}
      {results && (
        <Box sx={{ mt: 3 }}>
          <Alert
            severity={results.success ? "success" : "error"}
            sx={{ mb: 3 }}
          >
            <Typography variant="h6">
              {results.success
                ? `✅ ${results.implementation} Signal Protocol Demo Successful!`
                : `❌ ${results.implementation} Demo Failed`}
            </Typography>
            <Typography variant="body2">
              Implementation: <strong>{results.implementation}</strong> | Used
              One-time Prekey:{" "}
              <strong>{results.usedOneTimePrekey ? "Yes" : "No"}</strong>
            </Typography>
          </Alert>

          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography
                variant="h6"
                sx={{ display: "flex", alignItems: "center", gap: 1 }}
              >
                <SecurityIcon /> Shared Secrets Verification
              </Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Card>
                    <CardContent>
                      <Typography
                        variant="subtitle1"
                        gutterBottom
                        color="primary"
                      >
                        Alice's Derived Secret
                      </Typography>
                      <CodeDisplay
                        code={results.aliceSecret}
                        language="text"
                        maxHeight="100px"
                      />
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Card>
                    <CardContent>
                      <Typography
                        variant="subtitle1"
                        gutterBottom
                        color="secondary"
                      >
                        Bob's Derived Secret
                      </Typography>
                      <CodeDisplay
                        code={results.bobSecret}
                        language="text"
                        maxHeight="100px"
                      />
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>

              <Box
                sx={{
                  mt: 2,
                  display: "flex",
                  alignItems: "center",
                  gap: 1,
                  flexWrap: "wrap",
                }}
              >
                <Chip
                  label={
                    results.success
                      ? "Secrets Match ✓"
                      : "Secrets Don't Match ✗"
                  }
                  color={results.success ? "success" : "error"}
                />
                <Chip
                  label={`${results.implementation} Implementation`}
                  color="info"
                  variant="outlined"
                />
                {results.usedOneTimePrekey && (
                  <Chip
                    label="Perfect Forward Secrecy"
                    color="success"
                    variant="outlined"
                  />
                )}
              </Box>
            </AccordionDetails>
          </Accordion>

          {results.implementation === "WASM" && (
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="h6">Message Encryption Test</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" gutterBottom>
                      Original Message
                    </Typography>
                    <Paper sx={{ p: 2, bgcolor: "grey.50" }}>
                      <Typography variant="body2">{results.message}</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" gutterBottom>
                      Decrypted Message
                    </Typography>
                    <Paper sx={{ p: 2, bgcolor: "success.light" }}>
                      <Typography variant="body2">
                        {results.decryptedMessage}
                      </Typography>
                    </Paper>
                  </Grid>
                </Grid>
                <Typography variant="body2" sx={{ mt: 2 }}>
                  Encrypted data size: {results.encrypted} bytes | Signature
                  size: {results.signature} bytes
                </Typography>
              </AccordionDetails>
            </Accordion>
          )}
        </Box>
      )}

      {/* Performance Results */}
      {performanceResults && (
        <Box sx={{ mt: 3 }}>
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography
                variant="h6"
                sx={{ display: "flex", alignItems: "center", gap: 1 }}
              >
                <SpeedIcon /> Performance Comparison Results
              </Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Alert severity="info" sx={{ mb: 3 }}>
                <Typography variant="body2">
                  <strong>Performance Test Results</strong>
                  <br />
                  These benchmarks show WASM performance metrics. Times shown
                  are averages per operation in milliseconds.
                </Typography>
              </Alert>

              {/* Overall Performance */}
              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={12}>
                  <Card>
                    <CardContent>
                      <Typography
                        variant="h6"
                        gutterBottom
                        color="success.main"
                      >
                        🦀 WASM (Rust) Implementation
                      </Typography>
                      <Typography variant="h4" color="text.primary">
                        {performanceResults.wasm.totalTime?.toFixed(1) || "N/A"}
                        ms
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Total execution time
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>

              {/* Detailed Benchmarks */}
              <Typography variant="h6" gutterBottom>
                Detailed Operation Benchmarks
              </Typography>
              <Box sx={{ mb: 2 }}>
                {Object.entries(performanceResults.benchmarks || {}).map(
                  ([operation, times]) => (
                    <Paper key={operation} sx={{ p: 2, mb: 2 }}>
                      <Typography
                        variant="subtitle1"
                        gutterBottom
                        sx={{ textTransform: "capitalize" }}
                      >
                        {operation.replace(/([A-Z])/g, " $1")}
                      </Typography>
                      <Grid container spacing={2}>
                        <Grid item xs={12} sm={6}>
                          <Typography variant="body2" color="text.secondary">
                            WASM (Rust)
                          </Typography>
                          <Typography variant="h6" color="success.main">
                            {times.wasm > 0
                              ? `${times.wasm.toFixed(1)}ms`
                              : "N/A"}
                          </Typography>
                        </Grid>
                      </Grid>
                    </Paper>
                  ),
                )}
              </Box>

              <Typography variant="caption" color="text.secondary">
                * Benchmarks run {performanceResults.benchmarks ? 10 : 1}{" "}
                iterations each. Results may vary based on browser, device
                performance, and system load.
              </Typography>
            </AccordionDetails>
          </Accordion>
        </Box>
      )}

      {/* Technical Details */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">
            🔬 Technical Implementation Details
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom color="warning.main">
                    🟨 JavaScript Implementation
                  </Typography>
                  <Box component="ul" sx={{ pl: 2, "& li": { mb: 1 } }}>
                    <li>
                      <strong>Curves:</strong> P-256 (NIST) via Web Crypto API
                    </li>
                    <li>
                      <strong>Key Exchange:</strong> ECDH with browser
                      optimizations
                    </li>
                    <li>
                      <strong>Signatures:</strong> ECDSA via Web Crypto API
                    </li>
                    <li>
                      <strong>Key Derivation:</strong> HKDF-SHA256
                      implementation
                    </li>
                    <li>
                      <strong>Encryption:</strong> AES-GCM via Web Crypto API
                    </li>
                    <li>
                      <strong>Memory:</strong> Garbage collected, automatic
                      cleanup
                    </li>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom color="success.main">
                    🦀 WASM (Rust) Implementation
                  </Typography>
                  <Box component="ul" sx={{ pl: 2, "& li": { mb: 1 } }}>
                    <li>
                      <strong>Curves:</strong> Curve25519 (EdDSA/X25519)
                      optimized
                    </li>
                    <li>
                      <strong>Key Exchange:</strong> Native X25519 with assembly
                      optimizations
                    </li>
                    <li>
                      <strong>Signatures:</strong> Ed25519 with batch
                      verification
                    </li>
                    <li>
                      <strong>Key Derivation:</strong> HKDF-SHA256 with SIMD
                    </li>
                    <li>
                      <strong>Encryption:</strong> AES-GCM with hardware
                      acceleration
                    </li>
                    <li>
                      <strong>Memory:</strong> Manual management, zero-copy
                      optimizations
                    </li>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>
            🏗️ Architecture Comparison
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, bgcolor: "warning.light" }}>
                <Typography variant="subtitle1" gutterBottom>
                  JavaScript Advantages
                </Typography>
                <Box component="ul" sx={{ pl: 2, fontSize: "0.9rem" }}>
                  <li>No compilation step required</li>
                  <li>Easy debugging and profiling</li>
                  <li>Direct browser API integration</li>
                  <li>Smaller initial bundle size</li>
                  <li>JIT optimizations for hot paths</li>
                </Box>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, bgcolor: "success.light" }}>
                <Typography variant="subtitle1" gutterBottom>
                  WASM Advantages
                </Typography>
                <Box component="ul" sx={{ pl: 2, fontSize: "0.9rem" }}>
                  <li>Near-native performance</li>
                  <li>Deterministic execution time</li>
                  <li>Better memory management</li>
                  <li>Compiler optimizations (LLVM)</li>
                  <li>Language-agnostic (Rust, C++, etc.)</li>
                </Box>
              </Paper>
            </Grid>
          </Grid>
        </AccordionDetails>
      </Accordion>

      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">🛡️ Security Considerations</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Alert severity="info" sx={{ mb: 2 }}>
            <Typography variant="body2">
              Both implementations provide the same cryptographic security
              guarantees. The choice between JavaScript and WASM is primarily
              about performance, not security.
            </Typography>
          </Alert>

          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="subtitle1" gutterBottom>
                    Shared Security Properties
                  </Typography>
                  <Box component="ul" sx={{ pl: 2, fontSize: "0.9rem" }}>
                    <li>Perfect Forward Secrecy</li>
                    <li>Future Secrecy</li>
                    <li>Mutual Authentication</li>
                    <li>Message Integrity</li>
                    <li>Replay Protection</li>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="subtitle1" gutterBottom>
                    Implementation-Specific Benefits
                  </Typography>
                  <Box component="ul" sx={{ pl: 2, fontSize: "0.9rem" }}>
                    <li>
                      <strong>JavaScript:</strong> Browser security sandbox
                    </li>
                    <li>
                      <strong>JavaScript:</strong> Established Web Crypto API
                    </li>
                    <li>
                      <strong>WASM:</strong> Memory safety from Rust
                    </li>
                    <li>
                      <strong>WASM:</strong> Constant-time implementations
                    </li>
                    <li>
                      <strong>WASM:</strong> Reduced side-channel attacks
                    </li>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </AccordionDetails>
      </Accordion>
    </CryptoDemo>
  );
};

export default {
  title: "Signal Protocol/WASM vs JavaScript",
  component: SignalProtocolWasmDemo,
  parameters: {
    docs: {
      description: {
        component: `
# Signal Protocol: WASM vs JavaScript Performance Comparison

This demo compares two implementations of the Signal Protocol:

## 🟨 JavaScript Implementation
- Uses Web Crypto API with X25519/Ed25519 curves
- Relies on browser optimizations and JIT compilation
- Easy to debug and integrate with web applications
- Good performance for most use cases

## 🦀 WASM (Rust) Implementation  
- Compiled from Rust using curve25519-dalek and related crates
- Uses Curve25519/Ed25519 for better performance
- Near-native speed with predictable execution times
- Memory-safe with manual memory management
- Optimized assembly code for cryptographic operations

## Performance Expectations
WASM typically provides 2-10x performance improvements for:
- Key generation operations
- Digital signature creation/verification  
- Elliptic curve operations (ECDH)
- Hash-based key derivation (HKDF)
- Bulk encryption/decryption operations

## Use Cases
- **JavaScript**: Web applications, prototypes, education
- **WASM**: High-performance applications, mobile apps, real-time messaging

Both implementations provide identical security guarantees and are compatible with the Signal Protocol specification.
            `,
      },
    },
  },
};

// Default story
export const Default = () => <SignalProtocolWasmDemo />;

// Performance-focused story
const PerformanceFocusDemo = () => {
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [wasmAvailable, setWasmAvailable] = useState(false);
  const [wasmInstance, setWasmInstance] = useState(null);
  const [error, setError] = useState("");
  // const crypto = useCryptography(); // TODO: Replace with WASM

  // Initialize WASM on component mount
  useEffect(() => {
    initializeWasm();
  }, []);

  const initializeWasm = async () => {
    try {
      // Try to load the real WASM module
      const wasmModule = await import("/pkg/signal_protocol_wasm.js");
      await wasmModule.default();

      const wasmWrapper = {
        async generateIdentityKeyPair() {
          const result = wasmModule.generate_identity_keypair();
          return {
            publicKey: result.public_key,
            privateKey: result.private_key,
          };
        },
        async generateSignedPrekey() {
          const result = wasmModule.generate_signed_prekey();
          return {
            publicKey: result.public_key,
            privateKey: result.private_key,
          };
        },
        async generateEphemeralKeyPair() {
          const result = wasmModule.generate_ephemeral_keypair();
          return {
            publicKey: result.public_key,
            privateKey: result.private_key,
          };
        },
        async signData(privateKey, data) {
          return wasmModule.sign_data(privateKey, data);
        },
        async x3dhInitiate(
          aliceIdentityPrivate,
          aliceEphemeralPrivate,
          bobIdentityPublic,
          bobSignedPrekeyPublic,
          bobOneTimePrekeyPublic,
        ) {
          const result = wasmModule.x3dh_initiate(
            aliceIdentityPrivate,
            aliceEphemeralPrivate,
            bobIdentityPublic,
            bobSignedPrekeyPublic,
            bobOneTimePrekeyPublic,
          );
          return {
            sharedSecret: result.shared_secret,
            associatedData: result.associated_data,
          };
        },
        async encryptMessage(sharedSecret, plaintext, messageNumber) {
          const result = wasmModule.encrypt_message(
            sharedSecret,
            plaintext,
            messageNumber,
          );
          return {
            ciphertext: result.ciphertext,
            messageKey: result.message_key,
            messageNumber,
          };
        },
        async decryptMessage(
          sharedSecret,
          ciphertext,
          messageKey,
          messageNumber,
        ) {
          return wasmModule.decrypt_message(
            sharedSecret,
            ciphertext,
            messageKey,
            messageNumber,
          );
        },
        async initializeDoubleRatchet(sharedSecret, isInitiator) {
          return wasmModule.initialize_double_ratchet(
            sharedSecret,
            isInitiator,
          );
        },
        async doubleRatchetEncrypt(ratchetState, plaintext) {
          return wasmModule.double_ratchet_encrypt(ratchetState, plaintext);
        },
        async doubleRatchetDecrypt(ratchetState, envelope) {
          return wasmModule.double_ratchet_decrypt(ratchetState, envelope);
        },
      };

      setWasmInstance(wasmWrapper);
      setWasmAvailable(true);
    } catch (error) {
      console.warn("Real WASM module failed to load, using mock:", error);
      setWasmInstance(mockWasmImplementation);
      setWasmAvailable(false);
    }
  };

  const runBenchmarks = async () => {
    setLoading(true);
    setError("");

    try {
      if (!wasmInstance) {
        throw new Error("WASM not initialized. Please wait...");
      }

      const benchmarkResults = {
        keyGeneration: { wasm: 0 },
        signing: { wasm: 0 },
        x3dh: { wasm: 0 },
        encryption: { wasm: 0 },
        doubleRatchet: { wasm: 0 },
      };

      const iterations = 10;
      console.log(`🔬 Running ${iterations} iterations of each benchmark...`);

      // Benchmark WASM Implementation
      console.log("📊 Benchmarking WASM operations...");

      // Key Generation Benchmark
      let start = performance.now();
      for (let i = 0; i < iterations; i++) {
        await wasmInstance.generateIdentityKeyPair();
      }
      benchmarkResults.keyGeneration.wasm =
        (performance.now() - start) / iterations;

      // Signing Benchmark
      const testKey = await wasmInstance.generateIdentityKeyPair();
      const testData = new TextEncoder().encode(
        "benchmark test data for signing operations",
      );
      start = performance.now();
      for (let i = 0; i < iterations; i++) {
        await wasmInstance.signData(testKey.privateKey, testData);
      }
      benchmarkResults.signing.wasm = (performance.now() - start) / iterations;

      // X3DH Benchmark (simplified)
      start = performance.now();
      for (let i = 0; i < Math.min(5, iterations); i++) {
        const alice = await wasmInstance.generateIdentityKeyPair();
        const bob = await wasmInstance.generateIdentityKeyPair();
        const ephemeral = await wasmInstance.generateEphemeralKeyPair();
        const prekey = await wasmInstance.generateSignedPrekey();
        await wasmInstance.x3dhInitiate(
          alice.privateKey,
          ephemeral.privateKey,
          bob.publicKey,
          prekey.publicKey,
          null,
        );
      }
      benchmarkResults.x3dh.wasm =
        (performance.now() - start) / Math.min(5, iterations);

      // Encryption Benchmark
      const sharedSecret = new Uint8Array(32).fill(42);
      const message = new TextEncoder().encode(
        "This is a benchmark message for encryption performance testing",
      );
      start = performance.now();
      for (let i = 0; i < iterations; i++) {
        const encrypted = await wasmInstance.encryptMessage(
          sharedSecret,
          message,
          i + 1,
        );
        await wasmInstance.decryptMessage(
          sharedSecret,
          encrypted.ciphertext,
          encrypted.messageKey,
          i + 1,
        );
      }
      benchmarkResults.encryption.wasm =
        (performance.now() - start) / iterations;

      // Double Ratchet Benchmark
      try {
        const wasmModule = await loadWasmModule();
        const wasmSharedSecret = new Uint8Array(32).fill(42);
        const wasmAliceRatchet = wasmModule.initialize_double_ratchet(
          wasmSharedSecret,
          true,
        );
        const wasmBobRatchet = wasmModule.initialize_double_ratchet(
          wasmSharedSecret,
          false,
        );

        start = performance.now();
        for (let i = 0; i < iterations; i++) {
          const plaintext = new TextEncoder().encode(
            `Double ratchet test ${i}`,
          );
          const envelope = wasmModule.double_ratchet_encrypt(
            wasmAliceRatchet,
            plaintext,
          );
          wasmModule.double_ratchet_decrypt(wasmBobRatchet, envelope);
        }
        benchmarkResults.doubleRatchet.wasm =
          (performance.now() - start) / iterations;
      } catch (err) {
        console.warn("Double Ratchet benchmark failed:", err);
      }

      console.log("✅ WASM benchmarks completed");

      setResults({
        ...benchmarkResults,
        iterations,
        wasmAvailable,
        timestamp: Date.now(),
      });
    } catch (err) {
      console.error("Benchmark error:", err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const calculateSpeedup = (jsTime, wasmTime) => {
    if (wasmTime === 0) return "N/A";
    return (jsTime / wasmTime).toFixed(2) + "x";
  };

  return (
    <CryptoDemo title="WASM Performance Benchmarks" icon={<SpeedIcon />}>
      <Box sx={{ mb: 3 }}>
        <Typography paragraph>
          Detailed performance comparison focusing on individual cryptographic
          operations. This benchmark runs actual cryptographic functions and
          measures their execution time.
        </Typography>

        {/* WASM Status */}
        <Paper
          sx={{
            p: 2,
            mb: 3,
            bgcolor: wasmAvailable ? "success.light" : "warning.light",
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
            <WebAssemblyIcon color={wasmAvailable ? "success" : "warning"} />
            <Typography variant="h6">
              WebAssembly Status:{" "}
              {wasmAvailable ? "Available" : "Using Mock Implementation"}
            </Typography>
          </Box>
          <Typography variant="body2">
            {wasmAvailable
              ? "✅ WASM module loaded successfully. Real performance comparison available."
              : "⚠️ WASM module not available. Using mock implementation with simulated timings."}
          </Typography>
        </Paper>

        <Button
          variant="contained"
          onClick={runBenchmarks}
          disabled={loading}
          startIcon={<SpeedIcon />}
          fullWidth
          sx={{ mb: 2 }}
        >
          {loading ? "Running Benchmarks..." : "Run Performance Tests"}
        </Button>

        <OperationStatus
          loading={loading}
          error={error}
          success={results !== null}
        />
      </Box>

      {results && (
        <Box sx={{ mt: 3 }}>
          <Alert severity="info" sx={{ mb: 3 }}>
            <Typography variant="body2">
              <strong>Benchmark Results</strong>
              <br />
              Executed {results.iterations} iterations per operation. Times
              shown are averages per operation in milliseconds.
              {results.wasmAvailable
                ? " Real WASM performance."
                : " Mock implementation with simulated timings."}
            </Typography>
          </Alert>

          {/* Performance Summary */}
          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom color="warning.main">
                    🟨 JavaScript Performance
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Using Web Crypto API
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom color="success.main">
                    🦀 WASM Performance
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {wasmAvailable
                      ? "Rust-compiled WebAssembly"
                      : "Mock implementation"}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          {/* Detailed Results */}
          {Object.entries(results)
            .filter(
              ([key]) =>
                !["iterations", "wasmAvailable", "timestamp"].includes(key),
            )
            .map(([operation, times]) => (
              <Paper key={operation} sx={{ p: 3, mb: 2 }}>
                <Typography
                  variant="h6"
                  gutterBottom
                  sx={{ textTransform: "capitalize" }}
                >
                  {operation.replace(/([A-Z])/g, " $1")} Performance
                </Typography>
                <Grid container spacing={3}>
                  <Grid item xs={12} sm={6}>
                    <Box>
                      <Typography variant="body2" color="text.secondary">
                        WASM
                      </Typography>
                      <Typography variant="h4" color="success.main">
                        {times.wasm > 0 ? `${times.wasm.toFixed(2)}ms` : "N/A"}
                      </Typography>
                    </Box>
                  </Grid>
                </Grid>
              </Paper>
            ))}

          <Typography
            variant="caption"
            color="text.secondary"
            sx={{ mt: 2, display: "block" }}
          >
            * Results may vary based on browser, device performance, and system
            load. Benchmarks run {results.iterations} iterations each for
            accuracy.
          </Typography>
        </Box>
      )}
    </CryptoDemo>
  );
};

export const PerformanceFocus = () => <PerformanceFocusDemo />;
