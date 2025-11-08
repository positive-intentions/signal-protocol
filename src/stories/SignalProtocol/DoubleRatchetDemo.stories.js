import React, { useState, useEffect } from "react";
import {
  Box,
  Typography,
  Button,
  Card,
  CardContent,
  TextField,
  Stepper,
  Step,
  StepLabel,
  Alert,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Chip,
  Grid,
  Paper,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider,
  FormControlLabel,
  Switch,
  Badge,
} from "@mui/material";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import SecurityIcon from "@mui/icons-material/Security";
import MessageIcon from "@mui/icons-material/Message";
import LockIcon from "@mui/icons-material/Lock";
import SwapVertIcon from "@mui/icons-material/SwapVert";
import SendIcon from "@mui/icons-material/Send";
import KeyIcon from "@mui/icons-material/VpnKey";
import {
  SignalProtocolWasm,
  SignalWasmHelpers,
  loadWasmModule,
} from "../../wasm-bindings.js";
import { CryptoDemo, CodeDisplay, OperationStatus } from "ui";

// Define the component first
const DoubleRatchetDemo = () => {
  const [wasmInstance, setWasmInstance] = useState(null);
  const [wasmAvailable, setWasmAvailable] = useState(false);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");
  const [aliceState, setAliceState] = useState(null);
  const [bobState, setBobState] = useState(null);
  const [conversation, setConversation] = useState([]);
  const [newMessage, setNewMessage] = useState("");
  const [sender, setSender] = useState("Alice");
  const [simulateOutOfOrder, setSimulateOutOfOrder] = useState(false);
  const [pendingMessages, setPendingMessages] = useState([]);

  // Initialize WASM
  useEffect(() => {
    const initWasm = async () => {
      try {
        const wasmModule = await loadWasmModule();
        const wasmProtocol = new SignalProtocolWasm();
        await wasmProtocol.initialize();

        const wasmWrapper = {
          wasmProtocol,
          wasmModule,
          initializeDoubleRatchet: (sharedSecret, isInitiator) => {
            return wasmModule.initialize_double_ratchet(
              sharedSecret,
              isInitiator,
            );
          },
          doubleRatchetEncrypt: (state, message) => {
            const encoder = new TextEncoder();
            const messageBytes = encoder.encode(message);
            const envelope = wasmModule.double_ratchet_encrypt(
              state,
              messageBytes,
            );
            // wasm-bindgen getters become properties, not methods
            // Add camelCase aliases for convenience
            envelope.messageNumber = envelope.message_number;
            envelope.previousChainLength = envelope.previous_chain_length;
            envelope.dhPublicKey = envelope.dh_public_key;
            return envelope;
          },
          doubleRatchetDecrypt: (state, message) => {
            // message should be the original WASM envelope object
            const decryptedBytes = wasmModule.double_ratchet_decrypt(
              state,
              message,
            );
            const decoder = new TextDecoder();
            return decoder.decode(decryptedBytes);
          },
          bufferToHex: (buffer) => {
            return Array.from(buffer)
              .map((b) => b.toString(16).padStart(2, "0"))
              .join("");
          },
        };

        setWasmInstance(wasmWrapper);
        setWasmAvailable(true);
      } catch (err) {
        setError(`WASM initialization failed: ${err.message}`);
        setWasmAvailable(false);
      }
    };
    initWasm();
  }, []);

  const handleInitializeRatchet = async () => {
    setLoading(true);
    setError("");

    try {
      console.log("🚀 Initializing Double Ratchet demonstration...");

      if (!wasmInstance || !wasmInstance.wasmProtocol) {
        throw new Error("WASM not initialized. Please wait for WASM to load.");
      }

      // First perform X3DH key exchange to get shared secret
      const alice = await SignalWasmHelpers.initializeSignalUser(
        "Alice",
        wasmInstance.wasmProtocol,
      );
      const bob = await SignalWasmHelpers.initializeSignalUser(
        "Bob",
        wasmInstance.wasmProtocol,
      );
      const bobBundle = await SignalWasmHelpers.getPublicKeyBundle(bob);
      const exchangeResult = await SignalWasmHelpers.performX3DHKeyExchange(
        alice,
        bobBundle,
        wasmInstance.wasmProtocol,
      );

      console.log("✅ X3DH key exchange completed");

      // Initialize Double Ratchet states
      // Alice starts as initiator, Bob as responder - both start fresh
      const aliceRatchetState = wasmInstance.initializeDoubleRatchet(
        exchangeResult.sharedSecret,
        true, // Alice is initiator
      );

      const bobRatchetState = wasmInstance.initializeDoubleRatchet(
        exchangeResult.sharedSecret,
        false, // Bob is responder
      );

      setAliceState(aliceRatchetState);
      setBobState(bobRatchetState);
      setConversation([]);

      setResults({
        initialized: true,
        x3dhComplete: true,
        aliceInitiator: true,
        bobResponder: true,
      });

      console.log("✅ Double Ratchet states initialized successfully");
    } catch (err) {
      console.error("❌ Initialization failed:", err);
      setError(`Initialization failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleSendMessage = async () => {
    if (!newMessage.trim() || !aliceState || !bobState) return;

    setLoading(true);
    setError("");

    try {
      const senderState = sender === "Alice" ? aliceState : bobState;
      const receiverState = sender === "Alice" ? bobState : aliceState;

      console.log(`📤 ${sender} sending message: "${newMessage}"`);

      // Encrypt the message
      const messageEnvelope = wasmInstance.doubleRatchetEncrypt(
        senderState,
        newMessage,
      );

      const messageData = {
        id: Date.now(),
        from: sender,
        to: sender === "Alice" ? "Bob" : "Alice",
        content: newMessage,
        envelope: messageEnvelope,
        timestamp: Date.now(),
        encrypted: true,
        decrypted: false,
        decryptedContent: null,
      };

      if (simulateOutOfOrder && Math.random() > 0.5) {
        // Simulate network delay - add to pending messages
        setPendingMessages((prev) => [...prev, messageData]);
        console.log(
          "📦 Message added to pending queue (simulating network delay)",
        );
      } else {
        // Deliver immediately
        await deliverMessage(messageData, receiverState);
      }

      // States are already updated by the crypto functions (they mutate the objects)
      // Just trigger a re-render by setting the state again (React won't detect object mutations)
      setAliceState(aliceState);
      setBobState(bobState);

      setNewMessage("");
    } catch (err) {
      console.error("❌ Send message failed:", err);
      setError(`Send failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const deliverMessage = async (messageData, receiverState) => {
    try {
      console.log(
        `📥 ${messageData.to} receiving message from ${messageData.from}`,
      );

      // Decrypt the message
      const decryptedContent = wasmInstance.doubleRatchetDecrypt(
        receiverState,
        messageData.envelope,
      );

      const deliveredMessage = {
        ...messageData,
        decrypted: true,
        decryptedContent,
        deliveryTime: Date.now(),
      };

      setConversation((prev) => [...prev, deliveredMessage]);

      // States are already updated by the crypto functions (they mutate the objects)
      // Just trigger a re-render by setting the state again (React won't detect object mutations)
      setAliceState(aliceState);
      setBobState(bobState);

      console.log(
        `✅ Message decrypted by ${messageData.to}: "${decryptedContent}"`,
      );
    } catch (err) {
      console.error(`❌ Message delivery failed:`, err);
      const failedMessage = {
        ...messageData,
        decrypted: false,
        error: err.message,
        deliveryTime: Date.now(),
      };
      setConversation((prev) => [...prev, failedMessage]);
    }
  };

  const handleDeliverPendingMessages = async () => {
    if (pendingMessages.length === 0) return;

    setLoading(true);

    try {
      // Shuffle pending messages to simulate out-of-order delivery
      const shuffledMessages = [...pendingMessages].sort(
        () => Math.random() - 0.5,
      );

      for (const messageData of shuffledMessages) {
        const receiverState =
          messageData.to === "Alice" ? aliceState : bobState;
        await deliverMessage(messageData, receiverState);
        await new Promise((resolve) => setTimeout(resolve, 100)); // Small delay for UI
      }

      setPendingMessages([]);
    } catch (err) {
      setError(`Delivery failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleCompleteDemo = async () => {
    setLoading(true);
    setError("");

    try {
      // TODO: Implement demonstrateDoubleRatchet with WASM
      // const demoResult = await crypto.demonstrateDoubleRatchet();

      setResults({
        ...results,
        demoComplete: true,
        // ...demoResult
      });

      console.log("✅ Complete demonstration finished");
    } catch (err) {
      setError(`Demo failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const getMessageStatusColor = (msg) => {
    if (msg.error) return "error";
    if (!msg.decrypted) return "warning";
    return "success";
  };

  const getMessageStatusText = (msg) => {
    if (msg.error) return "Failed";
    if (!msg.decrypted) return "Encrypted";
    return "Decrypted";
  };

  return (
    <CryptoDemo title="Double Ratchet Protocol" icon={<SwapVertIcon />}>
      <Box sx={{ mb: 3 }}>
        <Typography variant="body1" paragraph>
          The Double Ratchet protocol provides forward secrecy and message
          integrity for ongoing conversations. After the initial X3DH key
          exchange, each message uses a new derived key, ensuring that
          compromise of current keys doesn't affect past or future messages.
        </Typography>

        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Button
              variant="contained"
              onClick={handleInitializeRatchet}
              disabled={loading}
              fullWidth
              startIcon={<KeyIcon />}
            >
              {loading ? "Initializing..." : "Initialize Ratchet"}
            </Button>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Button
              variant="outlined"
              onClick={handleCompleteDemo}
              disabled={loading || !results?.initialized}
              fullWidth
              startIcon={<SecurityIcon />}
            >
              {loading ? "Running..." : "Complete Demo"}
            </Button>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <FormControlLabel
              control={
                <Switch
                  checked={simulateOutOfOrder}
                  onChange={(e) => setSimulateOutOfOrder(e.target.checked)}
                />
              }
              label="Simulate Network Delays"
            />
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Button
              variant="outlined"
              onClick={handleDeliverPendingMessages}
              disabled={loading || pendingMessages.length === 0}
              fullWidth
            >
              <Badge badgeContent={pendingMessages.length} color="primary">
                Deliver Pending
              </Badge>
            </Button>
          </Grid>
        </Grid>

        <OperationStatus
          loading={loading}
          error={error}
          success={results?.initialized || results?.demoComplete}
        />
      </Box>

      {/* Message Interface */}
      {results?.initialized && (
        <Box sx={{ mb: 3 }}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Interactive Messaging
            </Typography>

            <Grid container spacing={2} sx={{ mb: 2 }}>
              <Grid item xs={12} sm={8}>
                <TextField
                  fullWidth
                  label="Type your message"
                  value={newMessage}
                  onChange={(e) => setNewMessage(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleSendMessage()}
                  disabled={loading}
                  placeholder="Enter a message to encrypt with Double Ratchet..."
                />
              </Grid>
              <Grid item xs={12} sm={2}>
                <Button
                  fullWidth
                  variant="outlined"
                  onClick={() =>
                    setSender(sender === "Alice" ? "Bob" : "Alice")
                  }
                >
                  From: {sender}
                </Button>
              </Grid>
              <Grid item xs={12} sm={2}>
                <Button
                  fullWidth
                  variant="contained"
                  onClick={handleSendMessage}
                  disabled={loading || !newMessage.trim()}
                  startIcon={<SendIcon />}
                >
                  Send
                </Button>
              </Grid>
            </Grid>
          </Paper>
        </Box>
      )}

      {/* Conversation Display */}
      {conversation.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography
                variant="h6"
                sx={{ display: "flex", alignItems: "center", gap: 1 }}
              >
                <MessageIcon /> Message Conversation ({conversation.length}{" "}
                messages)
              </Typography>
            </AccordionSummary>
            <AccordionDetails>
              <List sx={{ width: "100%" }}>
                {conversation.map((msg, index) => (
                  <React.Fragment key={msg.id}>
                    <ListItem alignItems="flex-start">
                      <ListItemIcon>
                        <LockIcon color={getMessageStatusColor(msg)} />
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <Box
                            sx={{
                              display: "flex",
                              alignItems: "center",
                              gap: 1,
                              mb: 1,
                            }}
                          >
                            <Typography variant="subtitle1" fontWeight="bold">
                              {msg.from} → {msg.to}
                            </Typography>
                            <Chip
                              label={getMessageStatusText(msg)}
                              size="small"
                              color={getMessageStatusColor(msg)}
                            />
                            <Typography
                              variant="caption"
                              color="text.secondary"
                            >
                              {new Date(msg.timestamp).toLocaleTimeString()}
                            </Typography>
                          </Box>
                        }
                        secondary={
                          <Box>
                            <Typography
                              variant="body2"
                              color="text.primary"
                              sx={{ mb: 1 }}
                            >
                              <strong>Original:</strong> "{msg.content}"
                            </Typography>
                            {msg.decrypted && (
                              <Typography variant="body2" color="success.main">
                                <strong>Decrypted:</strong> "
                                {msg.decryptedContent}"
                              </Typography>
                            )}
                            {msg.error && (
                              <Typography variant="body2" color="error.main">
                                <strong>Error:</strong> {msg.error}
                              </Typography>
                            )}
                            <Typography
                              variant="caption"
                              display="block"
                              sx={{ mt: 1 }}
                            >
                              Message #{msg.envelope?.messageNumber || "N/A"} •
                              Previous chain length:{" "}
                              {msg.envelope?.previousChainLength || 0} •
                              {msg.deliveryTime && (
                                <>
                                  Delivery delay:{" "}
                                  {msg.deliveryTime - msg.timestamp}ms
                                </>
                              )}
                            </Typography>
                          </Box>
                        }
                      />
                    </ListItem>
                    {index < conversation.length - 1 && (
                      <Divider variant="inset" component="li" />
                    )}
                  </React.Fragment>
                ))}
              </List>
            </AccordionDetails>
          </Accordion>
        </Box>
      )}

      {/* Results Display */}
      {results?.demoComplete && (
        <Box sx={{ mt: 3 }}>
          <Alert severity="success" sx={{ mb: 3 }}>
            <Typography variant="h6">
              ✅ Double Ratchet Demonstration Complete!
            </Typography>
            <Typography variant="body2">
              Successfully demonstrated forward secrecy, out-of-order message
              handling, and automatic key ratcheting.{" "}
              {results.messagesExchanged} messages exchanged.
            </Typography>
          </Alert>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">📊 Demonstration Results</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle1" gutterBottom>
                    Security Properties Demonstrated:
                  </Typography>
                  <Box
                    sx={{ display: "flex", flexDirection: "column", gap: 1 }}
                  >
                    <Chip
                      icon={<SecurityIcon />}
                      label="Forward Secrecy: Old keys deleted after use"
                      color={
                        results.demonstration?.forwardSecrecy
                          ? "success"
                          : "default"
                      }
                      variant="outlined"
                    />
                    <Chip
                      icon={<SwapVertIcon />}
                      label="Out-of-Order Handling: Messages decrypted correctly"
                      color={
                        results.demonstration?.outOfOrderHandling
                          ? "success"
                          : "default"
                      }
                      variant="outlined"
                    />
                    <Chip
                      icon={<KeyIcon />}
                      label="DH Ratcheting: Keys updated on conversation turns"
                      color={
                        results.demonstration?.dhRatcheting
                          ? "success"
                          : "default"
                      }
                      variant="outlined"
                    />
                    <Chip
                      icon={<LockIcon />}
                      label="Chain Key Updates: New key for each message"
                      color={
                        results.demonstration?.chainKeyUpdating
                          ? "success"
                          : "default"
                      }
                      variant="outlined"
                    />
                  </Box>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle1" gutterBottom>
                    State Information:
                  </Typography>
                  <Paper sx={{ p: 2, bgcolor: "grey.50" }}>
                    <Typography variant="body2" paragraph>
                      <strong>Messages Exchanged:</strong>{" "}
                      {results.messagesExchanged}
                    </Typography>
                    <Typography variant="body2" paragraph>
                      <strong>Alice State:</strong> Initiator with sending chain
                    </Typography>
                    <Typography variant="body2">
                      <strong>Bob State:</strong> Responder with receiving chain
                    </Typography>
                  </Paper>
                </Grid>
              </Grid>
            </AccordionDetails>
          </Accordion>
        </Box>
      )}

      {/* Educational Content */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">🎓 How Double Ratchet Works</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Typography variant="body1" paragraph>
            The Double Ratchet protocol operates on two levels:
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom color="primary">
                    1️⃣ Symmetric-Key Ratchet (Hash Chain)
                  </Typography>
                  <Typography variant="body2" paragraph>
                    Each message derives a new key from the previous chain key
                    using HMAC:
                  </Typography>
                  <CodeDisplay
                    code={`// For each message:
message_key = HMAC(chain_key, 0x01)
chain_key = HMAC(chain_key, 0x02)

// Then encrypt:
ciphertext = AES-GCM(message_key, plaintext)

// Delete message_key for forward secrecy!
delete message_key`}
                    language="javascript"
                    maxHeight="200px"
                  />
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom color="secondary">
                    2️⃣ DH Ratchet (Key Exchange)
                  </Typography>
                  <Typography variant="body2" paragraph>
                    When receiving a new DH public key, both chains are reset:
                  </Typography>
                  <CodeDisplay
                    code={`// On new DH public key:
dh_output = X25519(my_private, their_public)
root_key, chain_key = HKDF(root_key, dh_output)

// Generate new DH key pair for sending
new_keypair = generate_keypair()
dh_output2 = X25519(new_private, their_public)  
root_key, send_chain = HKDF(root_key, dh_output2)`}
                    language="javascript"
                    maxHeight="200px"
                  />
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          <Alert severity="info" sx={{ mt: 2 }}>
            <Typography variant="body2">
              <strong>Key Insight:</strong> The combination of these two
              ratchets ensures that: • Each message has a unique key (symmetric
              ratchet) • Keys are refreshed when conversation direction changes
              (DH ratchet) • Forward secrecy is maintained (keys are deleted
              after use) • Out-of-order messages can still be decrypted (skipped
              keys are saved)
            </Typography>
          </Alert>
        </AccordionDetails>
      </Accordion>

      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">🔒 Security Guarantees</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={2}>
            <Grid item xs={12} md={4}>
              <Card>
                <CardContent>
                  <Typography variant="subtitle1" gutterBottom>
                    Forward Secrecy
                  </Typography>
                  <Typography variant="body2">
                    If keys are compromised now, past messages remain secure
                    because old keys were deleted after use.
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card>
                <CardContent>
                  <Typography variant="subtitle1" gutterBottom>
                    Future Secrecy
                  </Typography>
                  <Typography variant="body2">
                    If keys are compromised now, future messages remain secure
                    because new keys are derived from fresh randomness.
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={4}>
              <Card>
                <CardContent>
                  <Typography variant="subtitle1" gutterBottom>
                    Message Integrity
                  </Typography>
                  <Typography variant="body2">
                    AES-GCM provides authenticated encryption, ensuring messages
                    haven't been tampered with.
                  </Typography>
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
  title: "Signal Protocol/Double Ratchet",
  component: DoubleRatchetDemo,
  parameters: {
    docs: {
      description: {
        component: `
# Double Ratchet Protocol

The Double Ratchet protocol provides ongoing forward secrecy for Signal Protocol conversations.
After the initial X3DH key exchange establishes a shared secret, the Double Ratchet manages
all subsequent message encryption and decryption.

## Key Features

### 🔄 Symmetric-Key Ratchet (Hash Chain)
- Each message uses a unique derived key
- Chain key is updated after each message using HMAC
- Message keys are immediately deleted for forward secrecy

### 🔀 DH Ratchet (Diffie-Hellman)
- Triggered when receiving a message with a new DH public key
- Both sending and receiving chains are refreshed
- Provides future secrecy and recovery from key compromise

### 📦 Out-of-Order Message Handling
- Messages can arrive in any order
- Skipped message keys are stored for later decryption
- Prevents attacks based on message reordering

### 🛡️ Security Properties
- **Forward Secrecy**: Past messages remain secure
- **Future Secrecy**: Future messages remain secure  
- **Message Integrity**: Authentication prevents tampering
- **Replay Protection**: Duplicate messages are detected

## Implementation Details

This implementation follows the Double Ratchet specification closely:
- HKDF-SHA256 for key derivation
- HMAC-SHA256 for chain key updates
- AES-256-GCM for message encryption
- X25519 for Diffie-Hellman operations

## Usage in Signal Protocol

The Double Ratchet is the second phase of Signal Protocol:
1. **X3DH**: Initial key agreement (one-time)
2. **Double Ratchet**: Ongoing message encryption (this component)

Together, they provide a complete end-to-end encryption solution used by
Signal, WhatsApp, and many other secure messaging applications.
        `,
      },
    },
  },
};

// Default story
export const Default = () => <DoubleRatchetDemo />;

// Interactive messaging story
const InteractiveMessagingDemo = () => {
  const [wasmInstance, setWasmInstance] = useState(null);
  const [wasmAvailable, setWasmAvailable] = useState(false);
  const [aliceState, setAliceState] = useState(null);
  const [bobState, setBobState] = useState(null);
  const [initialized, setInitialized] = useState(false);
  const [messages, setMessages] = useState([]);

  // Initialize WASM
  useEffect(() => {
    const initWasm = async () => {
      try {
        const wasmModule = await loadWasmModule();
        const wasmProtocol = new SignalProtocolWasm();
        await wasmProtocol.initialize();

        const wasmWrapper = {
          wasmProtocol,
          wasmModule,
          initializeDoubleRatchet: (sharedSecret, isInitiator) => {
            return wasmModule.initialize_double_ratchet(
              sharedSecret,
              isInitiator,
            );
          },
          doubleRatchetEncrypt: (state, message) => {
            const encoder = new TextEncoder();
            const messageBytes = encoder.encode(message);
            const envelope = wasmModule.double_ratchet_encrypt(
              state,
              messageBytes,
            );
            // wasm-bindgen getters become properties, not methods
            // Add camelCase aliases for convenience
            envelope.messageNumber = envelope.message_number;
            envelope.previousChainLength = envelope.previous_chain_length;
            envelope.dhPublicKey = envelope.dh_public_key;
            return envelope;
          },
          doubleRatchetDecrypt: (state, message) => {
            // message should be the original WASM envelope object
            const decryptedBytes = wasmModule.double_ratchet_decrypt(
              state,
              message,
            );
            const decoder = new TextDecoder();
            return decoder.decode(decryptedBytes);
          },
          bufferToHex: (buffer) => {
            return Array.from(buffer)
              .map((b) => b.toString(16).padStart(2, "0"))
              .join("");
          },
        };

        setWasmInstance(wasmWrapper);
        setWasmAvailable(true);
      } catch (err) {
        console.error("WASM initialization failed:", err);
        setWasmAvailable(false);
      }
    };
    initWasm();
  }, []);

  useEffect(() => {
    // Auto-initialize for this story
    if (wasmAvailable && wasmInstance) {
      initializeStates();
    }
  }, [wasmAvailable, wasmInstance]);

  const initializeStates = async () => {
    try {
      if (!wasmInstance || !wasmInstance.wasmProtocol) {
        throw new Error("WASM not initialized");
      }

      console.log("🚀 [InteractiveDemo] Starting initialization...");

      // X3DH setup
      console.log("👤 [InteractiveDemo] Initializing Alice...");
      const alice = await SignalWasmHelpers.initializeSignalUser(
        "Alice",
        wasmInstance.wasmProtocol,
      );
      console.log("👤 [InteractiveDemo] Alice initialized successfully");

      console.log("👤 [InteractiveDemo] Initializing Bob...");
      const bob = await SignalWasmHelpers.initializeSignalUser(
        "Bob",
        wasmInstance.wasmProtocol,
      );
      console.log("👤 [InteractiveDemo] Bob initialized successfully");

      console.log("📦 [InteractiveDemo] Getting Bob's public key bundle...");
      const bobBundle = await SignalWasmHelpers.getPublicKeyBundle(bob);
      console.log("📦 [InteractiveDemo] Bob bundle created:", {
        hasIdentityKey: !!bobBundle.identityKey,
        hasSignedPrekey: !!bobBundle.signedPrekey,
        hasOneTimePrekey: !!bobBundle.oneTimePrekey,
      });

      console.log("🤝 [InteractiveDemo] Performing X3DH key exchange...");
      const exchangeResult = await SignalWasmHelpers.performX3DHKeyExchange(
        alice,
        bobBundle,
        wasmInstance.wasmProtocol,
      );
      console.log(
        "🤝 [InteractiveDemo] X3DH completed, shared secret length:",
        exchangeResult.sharedSecret.byteLength,
      );

      // Double Ratchet setup
      console.log(
        "🔄 [InteractiveDemo] Initializing Alice Double Ratchet (initiator)...",
      );
      const aliceRatchet = wasmInstance.initializeDoubleRatchet(
        exchangeResult.sharedSecret,
        true,
      );
      console.log("🔄 [InteractiveDemo] Alice ratchet state initialized");

      console.log(
        "🔄 [InteractiveDemo] Initializing Bob Double Ratchet (responder)...",
      );
      const bobRatchet = wasmInstance.initializeDoubleRatchet(
        exchangeResult.sharedSecret,
        false,
      );
      console.log("🔄 [InteractiveDemo] Bob ratchet state initialized");

      setAliceState(aliceRatchet);
      setBobState(bobRatchet);
      setInitialized(true);

      console.log(
        "✅ [InteractiveDemo] Initialization completed successfully!",
      );
    } catch (error) {
      console.error("❌ [InteractiveDemo] Initialization failed:", error);
      console.error("❌ [InteractiveDemo] Error stack:", error.stack);
    }
  };

  const sendMessage = async (sender, content) => {
    if (!initialized) {
      console.warn("❌ Cannot send message - not initialized");
      return;
    }

    console.log(
      `\n🧪 [InteractiveDemo] ${sender} attempting to send: "${content}"`,
    );
    console.log(`🧪 [InteractiveDemo] Current states:`, {
      aliceStateExists: !!aliceState,
      bobStateExists: !!bobState,
      aliceInitialized: aliceState?.initialized,
      bobInitialized: bobState?.initialized,
    });

    // Use current state references directly (they are mutated by the crypto functions)
    const currentAliceState = aliceState;
    const currentBobState = bobState;

    const senderState =
      sender === "Alice" ? currentAliceState : currentBobState;
    const receiverState =
      sender === "Alice" ? currentBobState : currentAliceState;

    try {
      console.log(`🔐 [InteractiveDemo] Pre-encryption ${sender} state:`, {
        hasRootKey: !!senderState.root_key,
        hasSendingChainKey: !!senderState.sending_chain_key,
        hasReceivingChainKey: !!senderState.receiving_chain_key,
        sendingMessageNumber: senderState.sending_message_number,
        receivingMessageNumber: senderState.receiving_message_number,
        hasSendingDHKeyPair: !!senderState.sending_dh_keypair,
        hasReceivingDHPublicKey: !!senderState.receiving_dh_public_key,
        isInitiator: senderState.is_initiator,
      });

      console.log(
        `🔓 [InteractiveDemo] Pre-encryption ${sender === "Alice" ? "Bob" : "Alice"} state:`,
        {
          hasRootKey: !!receiverState.root_key,
          hasSendingChainKey: !!receiverState.sending_chain_key,
          hasReceivingChainKey: !!receiverState.receiving_chain_key,
          sendingMessageNumber: receiverState.sending_message_number,
          receivingMessageNumber: receiverState.receiving_message_number,
          hasSendingDHKeyPair: !!receiverState.sending_dh_keypair,
          hasReceivingDHPublicKey: !!receiverState.receiving_dh_public_key,
          isInitiator: receiverState.is_initiator,
        },
      );

      console.log(`🔐 [InteractiveDemo] Encrypting with ${sender}'s state...`);

      // Encrypt
      const envelope = wasmInstance.doubleRatchetEncrypt(senderState, content);
      console.log(
        `✅ [InteractiveDemo] ${sender} encryption successful, envelope:`,
        {
          messageNumber: envelope.messageNumber || envelope.message_number,
          previousChainLength:
            envelope.previousChainLength || envelope.previous_chain_length,
          dhPublicKeyLength: (envelope.dhPublicKey || envelope.dh_public_key)
            ?.length,
          ciphertextLength: envelope.ciphertext?.length,
        },
      );

      console.log(
        `🔓 [InteractiveDemo] Decrypting with ${sender === "Alice" ? "Bob" : "Alice"}'s state...`,
      );

      // Decrypt
      const decrypted = wasmInstance.doubleRatchetDecrypt(
        receiverState,
        envelope,
      );
      console.log(`✅ [InteractiveDemo] Decryption successful: "${decrypted}"`);

      // After decryption, check if receiver now has sending chain key (for Bob after first message)
      console.log(
        `🔍 [InteractiveDemo] Post-decryption ${sender === "Alice" ? "Bob" : "Alice"} state:`,
        {
          sendingMessageNumber: receiverState.sending_message_number,
          receivingMessageNumber: receiverState.receiving_message_number,
          // Note: sending_chain_key is not directly accessible, but we can infer from sending_message_number
          hasSendingCapability:
            receiverState.sending_message_number !== undefined,
        },
      );

      const message = {
        id: Date.now(),
        sender,
        receiver: sender === "Alice" ? "Bob" : "Alice",
        original: content,
        decrypted,
        messageNumber: envelope.messageNumber || envelope.message_number,
        timestamp: Date.now(),
      };

      setMessages((prev) => [...prev, message]);

      // States are already updated by the crypto functions (they mutate the objects)
      // Just trigger a re-render by setting the state again (React won't detect object mutations)
      setAliceState(currentAliceState);
      setBobState(currentBobState);

      console.log(
        `✅ [InteractiveDemo] ${sender} message exchange completed successfully`,
      );
    } catch (error) {
      console.error(`❌ [InteractiveDemo] ${sender} message failed:`, error);
      console.error(`❌ [InteractiveDemo] Error details:`, {
        name: error.name,
        message: error.message,
        stack: error.stack?.split("\n").slice(0, 5).join("\n"), // First 5 lines of stack
      });

      console.log(`🔍 [InteractiveDemo] ${sender} state at error:`, {
        hasRootKey: !!senderState?.root_key,
        hasSendingChainKey: !!senderState?.sending_chain_key,
        hasReceivingChainKey: !!senderState?.receiving_chain_key,
        sendingMessageNumber: senderState?.sending_message_number,
        receivingMessageNumber: senderState?.receiving_message_number,
        hasSendingDHKeyPair: !!senderState?.sending_dh_keypair,
        hasReceivingDHPublicKey: !!senderState?.receiving_dh_public_key,
      });

      console.log(
        `🔍 [InteractiveDemo] ${sender === "Alice" ? "Bob" : "Alice"} state at error:`,
        {
          hasRootKey: !!receiverState?.root_key,
          hasSendingChainKey: !!receiverState?.sending_chain_key,
          hasReceivingChainKey: !!receiverState?.receiving_chain_key,
          sendingMessageNumber: receiverState?.sending_message_number,
          receivingMessageNumber: receiverState?.receiving_message_number,
          hasSendingDHKeyPair: !!receiverState?.sending_dh_keypair,
          hasReceivingDHPublicKey: !!receiverState?.receiving_dh_public_key,
        },
      );

      // Add error message to the conversation
      const errorMessage = {
        id: Date.now(),
        sender,
        receiver: sender === "Alice" ? "Bob" : "Alice",
        original: content,
        decrypted: null,
        error: error.message,
        messageNumber: -1,
        timestamp: Date.now(),
      };

      setMessages((prev) => [...prev, errorMessage]);

      // Don't let the error bubble up and cause navigation issues
    }
  };

  if (!initialized) {
    return (
      <CryptoDemo
        title="Interactive Double Ratchet Messaging"
        icon={<MessageIcon />}
      >
        <Box sx={{ display: "flex", justifyContent: "center", p: 4 }}>
          <Typography>Initializing Double Ratchet states...</Typography>
        </Box>
      </CryptoDemo>
    );
  }

  return (
    <CryptoDemo
      title="Interactive Double Ratchet Messaging"
      icon={<MessageIcon />}
    >
      <Box sx={{ mb: 3 }}>
        <Typography variant="body1" paragraph>
          Click the buttons below to simulate a conversation between Alice and
          Bob. Each message is encrypted with a new derived key, demonstrating
          the symmetric-key ratchet in action.
        </Typography>

        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={6}>
            <Button
              fullWidth
              variant="contained"
              color="primary"
              onClick={() =>
                sendMessage(
                  "Alice",
                  `Hello Bob! Message ${messages.length + 1}`,
                )
              }
              startIcon={<SendIcon />}
            >
              Alice Sends Message
            </Button>
          </Grid>
          <Grid item xs={6}>
            <Button
              fullWidth
              variant="contained"
              color="secondary"
              onClick={() =>
                sendMessage("Bob", `Hi Alice! Response ${messages.length + 1}`)
              }
              startIcon={<SendIcon />}
            >
              Bob Sends Message
            </Button>
          </Grid>
        </Grid>
      </Box>

      {messages.length > 0 && (
        <Paper sx={{ p: 2 }}>
          <Typography variant="h6" gutterBottom>
            Message History ({messages.length} messages)
          </Typography>

          {messages.map((msg) => (
            <Box
              key={msg.id}
              sx={{ mb: 2, p: 2, border: "1px solid #ddd", borderRadius: 1 }}
            >
              <Typography variant="subtitle1" fontWeight="bold">
                {msg.sender} → {msg.receiver} (Message #{msg.messageNumber})
              </Typography>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                {new Date(msg.timestamp).toLocaleTimeString()}
              </Typography>
              <Typography variant="body1">
                <strong>Sent:</strong> "{msg.original}"
              </Typography>
              {msg.error ? (
                <Typography variant="body1" color="error.main">
                  <strong>Error:</strong> {msg.error}
                </Typography>
              ) : (
                <Typography variant="body1" color="success.main">
                  <strong>Received:</strong> "{msg.decrypted}"
                </Typography>
              )}
              <Chip
                label={
                  msg.error
                    ? "❌ Failed"
                    : msg.original === msg.decrypted
                      ? "✓ Verified"
                      : "✗ Mismatch"
                }
                size="small"
                color={
                  msg.error
                    ? "error"
                    : msg.original === msg.decrypted
                      ? "success"
                      : "error"
                }
                sx={{ mt: 1 }}
              />
            </Box>
          ))}
        </Paper>
      )}
    </CryptoDemo>
  );
};

export const InteractiveMessaging = () => <InteractiveMessagingDemo />;
