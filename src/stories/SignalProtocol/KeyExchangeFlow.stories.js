import React, { useState, useEffect } from "react";
import {
  Box,
  Typography,
  Button,
  Card,
  CardContent,
  Stepper,
  Step,
  StepLabel,
  Alert,
  Grid,
  Paper,
  Divider,
  Avatar,
  Chip,
  IconButton,
  Tooltip,
  TextField,
} from "@mui/material";
import PersonIcon from "@mui/icons-material/Person";
import KeyIcon from "@mui/icons-material/VpnKey";
import SwapHorizIcon from "@mui/icons-material/SwapHoriz";
import SecurityIcon from "@mui/icons-material/Security";
import VisibilityIcon from "@mui/icons-material/Visibility";
import VisibilityOffIcon from "@mui/icons-material/VisibilityOff";
import SendIcon from "@mui/icons-material/Send";
import LockIcon from "@mui/icons-material/Lock";
import MessageIcon from "@mui/icons-material/Message";
import LockOpenIcon from "@mui/icons-material/LockOpen";
import {
  SignalProtocolWasm,
  SignalWasmHelpers,
  loadWasmModule,
} from "../../wasm-bindings.js";
import { CryptoDemo, CodeDisplay, OperationStatus } from "ui";

const KeyExchangeFlowDemo = () => {
  const [wasmInstance, setWasmInstance] = useState(null);
  const [wasmReady, setWasmReady] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [alice, setAlice] = useState(null);
  const [bob, setBob] = useState(null);
  const [exchangeData, setExchangeData] = useState({});
  const [showPrivateKeys, setShowPrivateKeys] = useState(false);
  const [message, setMessage] = useState(
    "Hello Bob! This is a secure message from Alice 🔒",
  );
  const [encryptedMessage, setEncryptedMessage] = useState(null);
  const [decryptedMessage, setDecryptedMessage] = useState("");

  // Initialize WASM
  useEffect(() => {
    const initWasm = async () => {
      try {
        const wasmProtocol = new SignalProtocolWasm();
        await wasmProtocol.initialize();
        setWasmInstance(wasmProtocol);
        setWasmReady(true);
      } catch (err) {
        setError(`WASM initialization failed: ${err.message}`);
      }
    };
    initWasm();
  }, []);

  const steps = [
    "Setup: Initialize Alice & Bob",
    "Bob: Generate and Share Key Bundle",
    "Alice: Generate Ephemeral Key",
    "Alice: Perform Key Exchange Calculations",
    "Bob: Calculate Matching Secret",
    "Verification: Confirm Shared Secret",
    "Alice: Encrypt & Send Message",
    "Bob: Receive & Decrypt Message",
  ];

  const stepDescriptions = [
    "Both Alice and Bob generate their long-term identity keys, signed prekeys, and one-time prekeys",
    "Bob creates a public key bundle containing his identity key, signed prekey, and one-time prekeys for Alice to use",
    "Alice generates a fresh ephemeral key pair for this specific conversation",
    "Alice performs the X3DH key exchange using Bob's public keys and her own private keys",
    "Bob calculates the same shared secret using Alice's ephemeral public key and his private keys",
    "Both parties now have the same shared secret and can begin secure messaging",
    "Alice encrypts a message using the shared secret and sends it to Bob",
    "Bob receives the encrypted message and decrypts it using the same shared secret",
  ];

  const resetDemo = () => {
    setCurrentStep(0);
    setAlice(null);
    setBob(null);
    setExchangeData({});
    setEncryptedMessage(null);
    setDecryptedMessage("");
    setError("");
  };

  const executeStep = async (stepNumber) => {
    setLoading(true);
    setError("");

    try {
      switch (stepNumber) {
        case 0: // Initialize users
          if (!wasmInstance) {
            throw new Error("WASM not initialized");
          }
          const aliceUser = await SignalWasmHelpers.initializeSignalUser(
            "Alice",
            wasmInstance,
          );
          const bobUser = await SignalWasmHelpers.initializeSignalUser(
            "Bob",
            wasmInstance,
          );
          setAlice(aliceUser);
          setBob(bobUser);

          // Store key info for display
          const aliceIdentityPublic = Array.from(
            aliceUser.identityKeyPair.publicKey,
          )
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
          const bobIdentityPublic = Array.from(
            bobUser.identityKeyPair.publicKey,
          )
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");

          setExchangeData({
            aliceIdentityPublic,
            bobIdentityPublic,
          });
          break;

        case 1: // Bob creates key bundle
          const bobBundle = await SignalWasmHelpers.getPublicKeyBundle(bob);
          const bobSignedPrekeyPublic = Array.from(bobBundle.signedPrekey)
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
          const bobOneTimePrekeyPublic = bobBundle.oneTimePrekey
            ? Array.from(bobBundle.oneTimePrekey)
                .map((b) => b.toString(16).padStart(2, "0"))
                .join("")
            : null;

          setExchangeData((prev) => ({
            ...prev,
            bobBundle,
            bobSignedPrekeyPublic,
            bobOneTimePrekeyPublic,
          }));
          break;

        case 2: // Alice generates ephemeral key
          if (!wasmInstance) {
            throw new Error("WASM not initialized");
          }
          const aliceEphemeralPair =
            await wasmInstance.generateEphemeralKeyPair();
          const aliceEphemeralPublic = Array.from(aliceEphemeralPair.publicKey)
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");

          setExchangeData((prev) => ({
            ...prev,
            aliceEphemeralPair,
            aliceEphemeralPublic,
          }));
          break;

        case 3: // Alice performs X3DH
          if (!wasmInstance) {
            throw new Error("WASM not initialized");
          }
          const keyExchangeResult =
            await SignalWasmHelpers.performX3DHKeyExchange(
              alice,
              exchangeData.bobBundle,
              wasmInstance,
            );

          setExchangeData((prev) => ({
            ...prev,
            aliceSecret: Array.from(keyExchangeResult.sharedSecret)
              .map((b) => b.toString(16).padStart(2, "0"))
              .join(""),
            keyExchangeResult,
          }));
          break;

        case 4: // Bob calculates matching secret
          if (!wasmInstance) {
            throw new Error("WASM not initialized");
          }
          // Use WASM x3dhRespond to calculate Bob's matching secret
          // Find the one-time prekey private key if one was used
          const bobOneTimePrekeyPrivate =
            exchangeData.keyExchangeResult.usedOneTimePrekey &&
            exchangeData.bobBundle.oneTimePrekey
              ? bob.oneTimePrekeyPairs[0]?.privateKey // Use the first one-time prekey that was included in the bundle
              : null;

          const bobSecretResult = await wasmInstance.x3dhRespond(
            bob.identityKeyPair.privateKey,
            bob.identityKeyPair.publicKey,
            bob.signedPrekeyPair.privateKey,
            bobOneTimePrekeyPrivate,
            alice.identityKeyPair.publicKey,
            exchangeData.keyExchangeResult.aliceEphemeralPublic,
          );

          const bobSecretHex = Array.from(bobSecretResult.sharedSecret)
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");

          setExchangeData((prev) => ({
            ...prev,
            bobSecret: bobSecretHex,
          }));
          break;

        case 5: // Verification
          const secretsMatch =
            exchangeData.aliceSecret === exchangeData.bobSecret;
          setExchangeData((prev) => ({
            ...prev,
            secretsMatch,
          }));
          break;

        case 6: // Alice encrypts message
          if (!wasmInstance) {
            throw new Error("WASM not initialized");
          }
          // Convert hex shared secret to Uint8Array
          const aliceSecretBytes = new Uint8Array(
            exchangeData.aliceSecret
              .match(/.{2}/g)
              .map((byte) => parseInt(byte, 16)),
          );

          // Use WASM encryptMessage method
          const encryptedResult = await wasmInstance.encryptMessage(
            aliceSecretBytes,
            message,
            0, // message number
          );

          setEncryptedMessage({
            ciphertext: Array.from(encryptedResult.ciphertext)
              .map((b) => b.toString(16).padStart(2, "0"))
              .join(""),
            messageKey: Array.from(encryptedResult.messageKey)
              .map((b) => b.toString(16).padStart(2, "0"))
              .join(""),
            messageNumber: encryptedResult.messageNumber,
          });
          break;

        case 7: // Bob decrypts message
          if (!wasmInstance) {
            throw new Error("WASM not initialized");
          }
          // Convert hex shared secret to Uint8Array
          const bobSecretBytes = new Uint8Array(
            exchangeData.bobSecret
              .match(/.{2}/g)
              .map((byte) => parseInt(byte, 16)),
          );

          // Convert encrypted message hex strings back to Uint8Array
          const ciphertextBytes = new Uint8Array(
            encryptedMessage.ciphertext
              .match(/.{2}/g)
              .map((byte) => parseInt(byte, 16)),
          );
          const messageKeyBytes = new Uint8Array(
            encryptedMessage.messageKey
              .match(/.{2}/g)
              .map((byte) => parseInt(byte, 16)),
          );

          // Use WASM decryptMessage method
          const decryptedBytes = await wasmInstance.decryptMessage(
            bobSecretBytes,
            ciphertextBytes,
            messageKeyBytes,
            encryptedMessage.messageNumber,
          );

          // Convert decrypted bytes to string
          const decryptedText = new TextDecoder().decode(decryptedBytes);
          setDecryptedMessage(decryptedText);
          break;
      }

      setCurrentStep(stepNumber + 1);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const UserCard = ({ user, name, isAlice }) => (
    <Card
      sx={{ height: "100%", bgcolor: isAlice ? "primary.50" : "secondary.50" }}
    >
      <CardContent>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
          <Avatar sx={{ bgcolor: isAlice ? "primary.main" : "secondary.main" }}>
            <PersonIcon />
          </Avatar>
          <Typography variant="h6">{name}</Typography>
        </Box>

        {user && (
          <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <Box>
              <Typography
                variant="subtitle2"
                gutterBottom
                sx={{ display: "flex", alignItems: "center", gap: 1 }}
              >
                <KeyIcon fontSize="small" />
                Identity Key (Public)
              </Typography>
              <CodeDisplay
                code={
                  exchangeData[`${name.toLowerCase()}IdentityPublic`] ||
                  "Not generated yet"
                }
                language="text"
                maxHeight="60px"
              />
            </Box>

            {!isAlice && exchangeData.bobSignedPrekeyPublic && (
              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Signed Prekey (Public)
                </Typography>
                <CodeDisplay
                  code={exchangeData.bobSignedPrekeyPublic}
                  language="text"
                  maxHeight="60px"
                />
              </Box>
            )}

            {!isAlice && exchangeData.bobOneTimePrekeyPublic && (
              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  One-time Prekey (Public)
                </Typography>
                <CodeDisplay
                  code={exchangeData.bobOneTimePrekeyPublic}
                  language="text"
                  maxHeight="60px"
                />
              </Box>
            )}

            {isAlice && exchangeData.aliceEphemeralPublic && (
              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Ephemeral Key (Public)
                </Typography>
                <CodeDisplay
                  code={exchangeData.aliceEphemeralPublic}
                  language="text"
                  maxHeight="60px"
                />
                <Typography variant="caption" color="text.secondary">
                  Generated fresh for this conversation
                </Typography>
              </Box>
            )}

            {/* Message Input for Alice */}
            {isAlice && currentStep >= 6 && exchangeData.secretsMatch && (
              <Box sx={{ mt: 2 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Message to Encrypt
                </Typography>
                <TextField
                  fullWidth
                  multiline
                  rows={2}
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  placeholder="Enter message to encrypt..."
                  size="small"
                />
              </Box>
            )}

            {/* Show encrypted message on Alice's side */}
            {isAlice && encryptedMessage && (
              <Box sx={{ mt: 2 }}>
                <Typography
                  variant="subtitle2"
                  gutterBottom
                  color="warning.main"
                >
                  <LockIcon fontSize="small" sx={{ mr: 1 }} />
                  Encrypted Message
                </Typography>
                <CodeDisplay
                  code={
                    encryptedMessage.ciphertext ||
                    JSON.stringify(encryptedMessage, null, 2)
                  }
                  language="text"
                  maxHeight="100px"
                />
              </Box>
            )}

            {/* Show decrypted message on Bob's side */}
            {!isAlice && decryptedMessage && (
              <Box sx={{ mt: 2 }}>
                <Typography
                  variant="subtitle2"
                  gutterBottom
                  color="success.main"
                >
                  <LockOpenIcon fontSize="small" sx={{ mr: 1 }} />
                  Decrypted Message
                </Typography>
                <Alert severity="success" sx={{ mt: 1 }}>
                  <Typography variant="body1">"{decryptedMessage}"</Typography>
                </Alert>
              </Box>
            )}
          </Box>
        )}
      </CardContent>
    </Card>
  );

  const KeyExchangeVisualization = () => (
    <Paper sx={{ p: 2, bgcolor: "grey.50", textAlign: "center" }}>
      <Typography
        variant="h6"
        gutterBottom
        sx={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          gap: 1,
        }}
      >
        <SwapHorizIcon />
        {currentStep >= 7 ? "Secure Communication" : "Key Exchange Process"}
      </Typography>

      {currentStep >= 4 && exchangeData.aliceSecret && currentStep < 7 && (
        <Box sx={{ mt: 2 }}>
          <Typography variant="subtitle1" gutterBottom color="primary">
            Alice's Calculated Secret:
          </Typography>
          <CodeDisplay
            code={exchangeData.aliceSecret}
            language="text"
            maxHeight="80px"
          />
        </Box>
      )}

      {currentStep >= 5 && exchangeData.bobSecret && currentStep < 7 && (
        <Box sx={{ mt: 2 }}>
          <Typography variant="subtitle1" gutterBottom color="secondary">
            Bob's Calculated Secret:
          </Typography>
          <CodeDisplay
            code={exchangeData.bobSecret}
            language="text"
            maxHeight="80px"
          />
        </Box>
      )}

      {currentStep >= 6 && currentStep < 7 && (
        <Box sx={{ mt: 2 }}>
          <Alert severity={exchangeData.secretsMatch ? "success" : "error"}>
            <Typography variant="h6">
              {exchangeData.secretsMatch
                ? "✅ Secrets Match!"
                : "❌ Secrets Don't Match"}
            </Typography>
            <Typography variant="body2">
              {exchangeData.secretsMatch
                ? "Alice and Bob can now communicate securely using their shared secret"
                : "Something went wrong in the key exchange process"}
            </Typography>
          </Alert>
        </Box>
      )}

      {/* Message transmission visualization */}
      {currentStep >= 7 && (
        <Box sx={{ mt: 2 }}>
          <Box
            sx={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              mb: 2,
            }}
          >
            <Box sx={{ textAlign: "left" }}>
              <Typography variant="body2" color="primary">
                <strong>Alice</strong>
              </Typography>
              <Chip
                icon={<MessageIcon />}
                label="Sends Encrypted"
                size="small"
                color="primary"
                variant="outlined"
              />
            </Box>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <LockIcon color="warning" />
              <Typography variant="body2" color="text.secondary">
                Encrypted Channel
              </Typography>
              <SendIcon color="action" />
            </Box>
            <Box sx={{ textAlign: "right" }}>
              <Typography variant="body2" color="secondary">
                <strong>Bob</strong>
              </Typography>
              <Chip
                icon={<LockOpenIcon />}
                label="Receives Decrypted"
                size="small"
                color="secondary"
                variant="outlined"
              />
            </Box>
          </Box>

          {encryptedMessage && (
            <Box sx={{ mt: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                Message in Transit (Encrypted):
              </Typography>
              <Paper
                sx={{
                  p: 1,
                  bgcolor: "warning.light",
                  maxHeight: "100px",
                  overflow: "auto",
                }}
              >
                <Typography
                  variant="caption"
                  sx={{ fontFamily: "monospace", wordBreak: "break-all" }}
                >
                  {encryptedMessage?.ciphertext ||
                    JSON.stringify(encryptedMessage)}
                </Typography>
              </Paper>
            </Box>
          )}

          {decryptedMessage && (
            <Box sx={{ mt: 2 }}>
              <Alert severity="success" icon={<MessageIcon />}>
                <Typography variant="body1">
                  <strong>Secure Message Delivered:</strong> "{decryptedMessage}
                  "
                </Typography>
              </Alert>
            </Box>
          )}
        </Box>
      )}
    </Paper>
  );

  return (
    <CryptoDemo
      title="Signal Protocol: Step-by-Step Key Exchange"
      icon={<SecurityIcon />}
    >
      <Typography variant="body1" paragraph>
        This interactive demo shows exactly how Alice and Bob establish a shared
        secret using the Signal Protocol's X3DH key exchange. Follow each step
        to see the keys being generated and exchanged.
      </Typography>

      {/* Controls */}
      <Box
        sx={{
          mb: 3,
          display: "flex",
          gap: 2,
          alignItems: "center",
          flexWrap: "wrap",
        }}
      >
        <Button
          variant="contained"
          onClick={() => executeStep(currentStep)}
          disabled={loading || currentStep >= steps.length}
          startIcon={loading ? null : <SendIcon />}
        >
          {loading
            ? "Processing..."
            : currentStep === 0
              ? "Start Demo"
              : currentStep >= steps.length
                ? "Complete"
                : "Next Step"}
        </Button>

        <Button variant="outlined" onClick={resetDemo} disabled={loading}>
          Reset Demo
        </Button>

        <Tooltip title="Toggle private key visibility (for educational purposes)">
          <IconButton onClick={() => setShowPrivateKeys(!showPrivateKeys)}>
            {showPrivateKeys ? <VisibilityOffIcon /> : <VisibilityIcon />}
          </IconButton>
        </Tooltip>
      </Box>

      {/* Progress Stepper */}
      <Box sx={{ mb: 3 }}>
        <Stepper activeStep={currentStep} orientation="vertical">
          {steps.map((label, index) => (
            <Step key={label}>
              <StepLabel>
                <Typography variant="subtitle1">{label}</Typography>
                <Typography variant="body2" color="text.secondary">
                  {stepDescriptions[index]}
                </Typography>
              </StepLabel>
            </Step>
          ))}
        </Stepper>
      </Box>

      <OperationStatus loading={loading} error={error} />

      {/* Main Content */}
      <Grid container spacing={3}>
        {/* Alice's Side */}
        <Grid item xs={12} md={5}>
          <UserCard user={alice} name="Alice" isAlice={true} />
        </Grid>

        {/* Key Exchange Visualization */}
        <Grid item xs={12} md={2}>
          <KeyExchangeVisualization />
        </Grid>

        {/* Bob's Side */}
        <Grid item xs={12} md={5}>
          <UserCard user={bob} name="Bob" isAlice={false} />
        </Grid>
      </Grid>

      {/* Detailed Step Information */}
      {currentStep > 0 && (
        <Box sx={{ mt: 4 }}>
          <Typography
            variant="h6"
            gutterBottom
            sx={{ display: "flex", alignItems: "center", gap: 1 }}
          >
            <LockIcon />
            Cryptographic Operations Performed
          </Typography>

          <Paper sx={{ p: 2 }}>
            {currentStep >= 1 && (
              <Alert severity="info" sx={{ mb: 2 }}>
                <Typography variant="subtitle2">
                  Step 1: User Initialization
                </Typography>
                <Typography variant="body2">
                  • Alice and Bob each generate ECDH identity key pairs
                  (long-term)
                  <br />
                  • Bob generates a signed prekey pair and signs it with his
                  identity key
                  <br />• Bob generates one-time prekey pairs for forward
                  secrecy
                </Typography>
              </Alert>
            )}

            {currentStep >= 2 && (
              <Alert severity="info" sx={{ mb: 2 }}>
                <Typography variant="subtitle2">
                  Step 2: Public Key Bundle Creation
                </Typography>
                <Typography variant="body2">
                  • Bob creates a bundle containing his public identity key,
                  signed prekey, and one-time prekey
                  <br />
                  • This bundle is what Alice needs to initiate secure
                  communication
                  <br />• The signed prekey proves the keys are authentic
                  (signed by Bob's identity key)
                </Typography>
              </Alert>
            )}

            {currentStep >= 3 && (
              <Alert severity="warning" sx={{ mb: 2 }}>
                <Typography variant="subtitle2">
                  Step 3: Ephemeral Key Generation
                </Typography>
                <Typography variant="body2">
                  • Alice generates a fresh ECDH key pair just for this
                  conversation
                  <br />
                  • This ephemeral key provides forward secrecy
                  <br />• It will never be stored permanently and is deleted
                  after use
                </Typography>
              </Alert>
            )}

            {currentStep >= 4 && (
              <Alert severity="success" sx={{ mb: 2 }}>
                <Typography variant="subtitle2">
                  Step 4: Alice's X3DH Calculation
                </Typography>
                <Typography variant="body2">
                  Alice performs three (or four) Diffie-Hellman operations:
                  <br />
                  • DH1: Alice_Identity × Bob_SignedPrekey (mutual
                  authentication)
                  <br />
                  • DH2: Alice_Ephemeral × Bob_Identity (forward secrecy)
                  <br />
                  • DH3: Alice_Ephemeral × Bob_SignedPrekey (additional forward
                  secrecy)
                  <br />
                  {exchangeData.keyExchangeResult?.usedOneTimePrekey &&
                    "• DH4: Alice_Ephemeral × Bob_OneTimePrekey (perfect forward secrecy)"}
                  <br />• All results are concatenated and put through HKDF to
                  derive the final secret
                </Typography>
              </Alert>
            )}

            {currentStep >= 5 && (
              <Alert severity="success" sx={{ mb: 2 }}>
                <Typography variant="subtitle2">
                  Step 5: Bob's Matching Calculation
                </Typography>
                <Typography variant="body2">
                  Bob performs the same DH operations but with roles reversed:
                  <br />
                  • DH1: Bob_SignedPrekey × Alice_Identity
                  <br />
                  • DH2: Bob_Identity × Alice_Ephemeral
                  <br />
                  • DH3: Bob_SignedPrekey × Alice_Ephemeral
                  <br />
                  {exchangeData.keyExchangeResult?.usedOneTimePrekey &&
                    "• DH4: Bob_OneTimePrekey × Alice_Ephemeral"}
                  <br />• Same HKDF process produces identical shared secret
                </Typography>
              </Alert>
            )}

            {currentStep >= 6 && (
              <Alert severity={exchangeData.secretsMatch ? "success" : "error"}>
                <Typography variant="subtitle2">
                  Step 6: Verification Complete
                </Typography>
                <Typography variant="body2">
                  {exchangeData.secretsMatch
                    ? "✅ Both parties now have the same 256-bit shared secret. They can use this to derive encryption keys for secure messaging. The one-time prekey (if used) is now consumed and deleted."
                    : "❌ The secrets don't match, indicating an error in the key exchange process."}
                </Typography>
              </Alert>
            )}

            {currentStep >= 7 && (
              <Alert severity="info" sx={{ mb: 2 }}>
                <Typography variant="subtitle2">
                  Step 7: Message Encryption
                </Typography>
                <Typography variant="body2">
                  • Alice derives an AES-256-GCM key from the shared secret
                  <br />
                  • She encrypts her message with a random IV (initialization
                  vector)
                  <br />
                  • The encrypted data and IV are sent to Bob through the
                  insecure channel
                  <br />• Anyone intercepting this data cannot decrypt it
                  without the shared secret
                </Typography>
              </Alert>
            )}

            {currentStep >= 8 && (
              <Alert severity="success" sx={{ mb: 2 }}>
                <Typography variant="subtitle2">
                  Step 8: Message Decryption
                </Typography>
                <Typography variant="body2">
                  • Bob derives the same AES-256-GCM key from his copy of the
                  shared secret
                  <br />
                  • He uses this key and the received IV to decrypt the message
                  <br />
                  • The decrypted message matches Alice's original text
                  perfectly
                  <br />• ✅ End-to-end encryption is complete - only Alice and
                  Bob can read the message
                </Typography>
              </Alert>
            )}
          </Paper>
        </Box>
      )}

      {/* Security Properties Explanation */}
      {currentStep >= 6 && exchangeData.secretsMatch && (
        <Box sx={{ mt: 3 }}>
          <Typography variant="h6" gutterBottom>
            Security Properties Achieved
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6}>
              <Chip
                icon={<SecurityIcon />}
                label="Forward Secrecy"
                color="success"
                sx={{ mb: 1, mr: 1 }}
              />
              <Typography variant="body2">
                Past messages stay secure even if long-term keys are compromised
              </Typography>
            </Grid>
            <Grid item xs={12} sm={6}>
              <Chip
                icon={<SecurityIcon />}
                label="Mutual Authentication"
                color="success"
                sx={{ mb: 1, mr: 1 }}
              />
              <Typography variant="body2">
                Both parties verify each other's identity through signatures
              </Typography>
            </Grid>
          </Grid>
        </Box>
      )}
    </CryptoDemo>
  );
};

export default {
  title: "Signal Protocol/Key Exchange Flow",
  component: KeyExchangeFlowDemo,
  parameters: {
    docs: {
      description: {
        component: `
# Signal Protocol: Interactive Key Exchange Flow

This story provides a step-by-step walkthrough of how Alice and Bob establish a shared secret using the Signal Protocol's X3DH key exchange. Each step is explained in detail with visual representation of the keys being generated and exchanged.

## Educational Focus

This demo is designed specifically for understanding:
- How each key type is used in the protocol
- The step-by-step flow of information between parties  
- What cryptographic operations happen at each stage
- Why each step is necessary for security

## What You'll Learn

- **Key Hierarchy**: Identity keys, signed prekeys, one-time prekeys, and ephemeral keys
- **X3DH Process**: The sequence of Diffie-Hellman operations that create the shared secret
- **Security Properties**: How forward secrecy, authentication, and perfect forward secrecy are achieved
- **Practical Implementation**: Real cryptographic operations using Web Crypto API

Perfect for developers, students, or anyone wanting to understand how modern secure messaging works under the hood.
        `,
      },
    },
  },
};

export const InteractiveFlow = () => <KeyExchangeFlowDemo />;
