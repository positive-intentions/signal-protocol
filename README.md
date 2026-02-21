# Signal Protocol

[![CI](https://img.shields.io/github/actions/workflow/status/positive-intentions/signal-protocol/ci.yml?branch=staging)](https://github.com/positive-intentions/signal-protocol/actions/workflows/ci.yml)

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
- **Formal Verification**: hax/F\*, Rocq, Lean support for cryptographic proofs
- **Docker Support**: Fully containerized development environment

## Building

### Option 1: Using Docker (Recommended)

No local tool installation required. All dependencies are containerized.

```bash
# Build WASM (production) -> ./pkg
docker compose run build

# Build WASM (dev) -> ./pkg
docker compose run build-dev

# Build WASM for Node.js -> ./pkg-node
docker compose run build-node
```

### Option 2: Local Installation

#### Prerequisites

- Rust (install via [rustup](https://rustup.rs/))
- wasm-pack (install via `npm run install-wasm-pack` or [wasm-pack installer](https://rustwasm.github.io/wasm-pack/installer/))
- Node.js and npm

#### Build WASM

```bash
npm run build:wasm
```

This will compile the Rust code to WebAssembly and output files to the `pkg/` directory.

#### Build for Production

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
  wasmInstance,
);
const bob = await SignalWasmHelpers.initializeSignalUser("Bob", wasmInstance);

// Get public key bundle
const bobBundle = await SignalWasmHelpers.getPublicKeyBundle(bob);

// Perform X3DH key exchange
const exchangeResult = await SignalWasmHelpers.performX3DHKeyExchange(
  alice,
  bobBundle,
  wasmInstance,
);

// Initialize Double Ratchet
const wasmModule = await loadWasmModule();
const aliceState = wasmModule.initialize_double_ratchet(
  exchangeResult.sharedSecret,
  true, // isInitiator
);
const bobState = wasmModule.initialize_double_ratchet(
  exchangeResult.sharedSecret,
  false, // isInitiator
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

## Docker Commands

All development can be done inside Docker containers without installing tools locally.

```bash
# Build WASM
docker compose run build           # Production build -> ./pkg
docker compose run build-dev       # Dev build -> ./pkg
docker compose run build-node      # Node.js target -> ./pkg-node

# Testing
docker compose run test            # Run all tests
docker compose run test-rust       # Rust tests only
docker compose run test-wasm       # WASM tests only
docker compose run test-jest       # Jest tests only

# Development
docker compose up dev              # Start Storybook (localhost:6006)
docker compose up serve            # Serve production build (localhost:8084)
docker compose run shell           # Interactive shell in dev container

  # Formal Verification
  docker compose run verification    # Extract F* from Rust code
  docker compose run hax-fstar       # Extract F* specifically
  docker compose run hax-coq         # Extract Coq specifically
  docker compose run hax-lean        # Extract Lean specifically
  docker compose run proverif        # Run all ProVerif proofs
  docker compose run proverif-x3dh   # Run X3DH proofs
  docker compose run proverif-double-ratchet  # Run Double Ratchet proofs
  docker compose run formal-shell    # Interactive shell with hax/F*/ProVerif
  docker compose run coq-verify      # Verify all Rocq files
  docker compose run lean-verify     # Verify all Lean files
  docker compose run lean-shell      # Interactive Lean shell
```

## Formal Verification

This project supports formal verification using:

- **hax**: Translates Rust to F\*, Rocq (Coq), or Lean for formal proofs
- **ProVerif**: Cryptographic protocol verifier for X3DH and Double Ratchet

### Using hax

```bash
# Extract F* from signal-protocol-core
docker compose run hax-fstar

# Extract Rocq (Coq) from signal-protocol-core
docker compose run hax-rocq

# Extract Lean
docker compose run hax-lean

# Interactive shell with hax
docker compose run formal-shell
cargo hax into fstar --help
```

### Using Rocq Verification

```bash
# Extract Rocq from Rust code
docker compose run hax-coq

# Verify all Rocq files
docker compose run coq-verify

# Interactive Rocq shell
docker compose run coq-shell
# Inside shell:
cd signal-protocol-core/proofs/coq/extraction
make verify    # Verify all modules
make verify-lite  # Verify core modules only
make extract   # Extract only (no verification)
```

### Using Lean Verification

```bash
# Extract Lean from Rust code
docker compose run hax-lean

# Verify all Lean files
docker compose run lean-verify

# Interactive Lean shell
docker compose run lean-shell
# Inside shell:
cd signal-protocol-core/proofs/lean
lake build              # Build all Lean files
lake build <module>     # Build specific module
```

### Using ProVerif

# Run all ProVerif proofs

docker compose run proverif

# Run specific proofs

docker compose run proverif-x3dh
docker compose run proverif-double-ratchet

# Interactive ProVerif shell

docker compose run formal-shell
proverif formal-proofs/proverif/x3dh/x3dh_complete.pv

```

See `formal-proofs/README.md` for more details on the ProVerif models.

See `signal-protocol-core/proofs/README.md` for detailed setup of F\*, Rocq, and Lean verification.

## License

ISC
```
