# Signal Protocol

A Rust implementation of the Signal Protocol compiled to WebAssembly (WASM) for use in web browsers and Node.js environments.

## Overview

This repository contains a complete implementation of the Signal Protocol cryptographic protocol, including:

- **X3DH Key Exchange**: Extended Triple Diffie-Hellman key agreement protocol
- **Double Ratchet**: Forward-secure messaging protocol with automatic key rotation
- **Key Generation**: Identity keys, signed prekeys, one-time prekeys, and ephemeral keys
- **Message Encryption/Decryption**: AES-256-GCM encryption with authenticated data

## Features

- **Rust Implementation**: High-performance, memory-safe cryptographic operations
- **WebAssembly**: Compiled to WASM for browser and Node.js compatibility
- **TypeScript/JavaScript Bindings**: Easy-to-use JavaScript API
- **Storybook Demos**: Interactive browser-based demonstrations of all functionality
- **Comprehensive Tests**: Unit tests for Rust, WASM, and JavaScript bindings

## Building

### Prerequisites

- Rust (install via [rustup](https://rustup.rs/))
- wasm-pack (install via `npm run install-wasm-pack` or [wasm-pack installer](https://rustwasm.github.io/wasm-pack/installer/))
- Node.js and npm

### Build WASM

```bash
npm run build:wasm
```

This will compile the Rust code to WebAssembly and output files to the `pkg/` directory.

### Build for Production

```bash
npm run build:wasm:production
```

## Testing

### Run All Tests

```bash
npm test
```

This runs Jest tests with coverage reporting for the WASM bindings.

### Run Rust Tests

```bash
npm run test:rust
```

### Run WASM Tests

```bash
npm run test:wasm:node
```

### View Coverage

Coverage reports are generated in the `coverage/` directory. Open `coverage/lcov-report/index.html` in a browser to view detailed coverage.

## Development

### Storybook

Run Storybook to see interactive demos of all Signal Protocol functionality:

```bash
npm start
```

This starts Storybook on `http://localhost:6006` where you can test all WASM functionality in the browser.

### Watch Mode

Watch for Rust changes and rebuild WASM:

```bash
npm run watch:rust
```

## Usage

### JavaScript/TypeScript

```javascript
import {
  SignalProtocolWasm,
  SignalWasmHelpers,
  loadWasmModule,
} from "./wasm-bindings.js";

// Initialize WASM
const wasmInstance = new SignalProtocolWasm();
await wasmInstance.initialize();

// Initialize users
const alice = await SignalWasmHelpers.initializeSignalUser(
  "Alice",
  wasmInstance
);
const bob = await SignalWasmHelpers.initializeSignalUser("Bob", wasmInstance);

// Get public key bundle
const bobBundle = await SignalWasmHelpers.getPublicKeyBundle(bob);

// Perform X3DH key exchange
const exchangeResult = await SignalWasmHelpers.performX3DHKeyExchange(
  alice,
  bobBundle,
  wasmInstance
);

// Initialize Double Ratchet
const wasmModule = await loadWasmModule();
const aliceState = wasmModule.initialize_double_ratchet(
  exchangeResult.sharedSecret,
  true // isInitiator
);
const bobState = wasmModule.initialize_double_ratchet(
  exchangeResult.sharedSecret,
  false // isInitiator
);

// Encrypt and decrypt messages
const plaintext = new TextEncoder().encode("Hello, Bob!");
const encrypted = wasmModule.double_ratchet_encrypt(aliceState, plaintext);
const decrypted = wasmModule.double_ratchet_decrypt(bobState, encrypted);
const message = new TextDecoder().decode(decrypted);
```

## Project Structure

```
signal-protocol/
├── src/
│   ├── rust/              # Rust implementation
│   │   ├── crypto.rs      # Cryptographic primitives
│   │   ├── keys.rs         # Key generation
│   │   ├── x3dh.rs         # X3DH key exchange
│   │   ├── double_ratchet.rs  # Double Ratchet protocol
│   │   └── ...
│   ├── wasm-bindings.js   # JavaScript bindings for WASM
│   ├── stories/           # Storybook demos
│   └── tests/             # Test files
├── pkg/                   # Compiled WASM output
└── Cargo.toml             # Rust dependencies
```

## Module Federation

This package is configured for module federation and can be consumed by other applications. The bootstrap entry point (`src/bootstrap.tsx`) is set up for federation.

## License

ISC
