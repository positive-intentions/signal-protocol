# signal-protocol-gallery

Local-only Dioxus gallery for exercising [`signal-protocol-core`](../signal-protocol-core)
through interactive demos. UI chrome comes from
[`whatsup-ui`](https://github.com/positive-intentions/whatsup-ui) (`gallery` feature).

This crate is **not** part of the React Storybook / GitHub Pages deploy.

Demos still call **`signal-protocol-core` from Rust** (no `wasm-bindgen` façade). The
default target is **web** via Dioxus so you do not need GTK/WebKit desktop packages.

## Run (web — recommended)

```bash
cd signal-protocol-gallery
dx serve --bin signal-protocol-gallery --platform web
```

## Coverage report

Generate the llvm-cov HTML report (from the repo root), then open **Coverage** in the gallery sidebar (`/coverage`):

```bash
# from signal-protocol repo root
npm run test:rust:coverage
# equivalent:
# cargo +nightly llvm-cov --workspace --branch \
#   --ignore-filename-regex 'src/rust/tests\.rs|src/rust/wasm_tests\.rs' \
#   --html --output-dir signal-protocol-gallery/assets/coverage-html

cd signal-protocol-gallery
dx serve --bin signal-protocol-gallery --platform web
# open /coverage (sidebar Coverage link)
```

## Run (desktop — optional)

Desktop needs native linker deps (the error `cannot find -lxdo` means this package is missing):

```bash
sudo apt-get install -y libxdo-dev libwebkit2gtk-4.1-dev libgtk-3-dev
cd signal-protocol-gallery
cargo run --no-default-features --features desktop
# or
dx serve --bin signal-protocol-gallery --features desktop --platform desktop
```

## Stories

Each story is a **paced stepper** (Next / Back / Reset) with Alice/Bob panels,
teach-back logs, and Docs that match the live steps.

| Demo | Core APIs |
|------|-----------|
| Key generation | `generate_*`, `validate_x25519_public_key` |
| X3DH handshake | `x3dh_initiate_internal`, `x3dh_respond_internal` |
| Double Ratchet playground | `initialize_double_ratchet_internal`, encrypt/decrypt |
| Skipped / out-of-order | skip-key decrypt path |
| Full session | X3DH → DR → multi-message transcript |
| Error surface | negative paths → `SignalError` |

## Dependencies

- `signal-protocol-core` (path)
- `whatsup-ui` (git, features `gallery` + `web`/`desktop`), with a local `[patch]` to
  `../../whatsup-ui` until hostable gallery APIs are on the default branch
