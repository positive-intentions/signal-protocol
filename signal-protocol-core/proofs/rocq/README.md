# Signal Protocol Core - Rocq Verification

Rocq is the successor to the Coq Proof Assistant. See the [extraction directory](extraction/) for detailed setup and usage information.

## Quick Start

```bash
# Install Rocq
opam install rocq-prover

# Extract Rocq from Rust
cd signal-protocol-core
cargo-hax -C --no-default-features \; into coq

# Verify extracted files
cd proofs/rocq/extraction
make verify
```

## Docker

```bash
docker compose run hax-rocq      # Extract Rocq
docker compose run rocq-verify    # Verify Rocq files
docker compose run rocq-shell     # Interactive shell
```

## Documentation

See [extraction/README.md](extraction/README.md) for complete setup guide.
