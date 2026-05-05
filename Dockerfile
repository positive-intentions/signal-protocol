# ============================================
# Stage 1: Base image with common dependencies
# ============================================
FROM node:20-bookworm AS base

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Rust (stable)
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable

RUN rustup target add wasm32-unknown-unknown

# Install wasm-pack
RUN curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

WORKDIR /app

# ============================================
# Stage 2: Builder - install dependencies
# ============================================
FROM base AS builder

COPY package*.json ./
COPY Cargo.toml ./
COPY signal-protocol-core/Cargo.toml ./signal-protocol-core/
COPY signal-protocol-core/src ./signal-protocol-core/src/
COPY src ./src

RUN npm ci

# ============================================
# Stage 3: Development environment
# ============================================
FROM builder AS development

COPY . .

RUN mkdir -p ./Frontend && npm run build:wasm

CMD ["npm", "start"]

# ============================================
# Stage 4: Build WASM (web target)
# ============================================
FROM builder AS wasm-builder

COPY . .

RUN mkdir -p ./Frontend && npm run build:wasm:production

# ============================================
# Stage 5: Test runner
# ============================================
FROM builder AS test-runner

COPY . .

RUN npm run build:wasm:node

WORKDIR /app

CMD ["npm", "run", "test:rust"]

# ============================================
# Stage 6: Production build
# ============================================
FROM builder AS production-builder

COPY . .

RUN mkdir -p ./Frontend && npm run build

# ============================================
# Stage 7: Production server
# ============================================
FROM nginx:alpine AS production

COPY --from=production-builder /app/Frontend /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]

# ============================================
# Stage 8: Prover base (shared by hax + aeneas)
# ============================================
FROM debian:bookworm AS prover-base

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    curl \
    wget \
    unzip \
    build-essential \
    pkg-config \
    libssl-dev \
    libgmp-dev \
    libexpat1-dev \
    libgtk2.0-dev \
    git \
    opam \
    jq \
    m4 \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

ENV OPAMROOT=/root/.opam \
    PATH=/root/.opam/5.1.1/bin:/root/.cargo/bin:/root/.elan/bin:/root/.local/bin:$PATH

RUN opam init --disable-sandboxing --bare -y && \
    opam switch create 5.1.1 --no-switch && \
    opam switch 5.1.1 && \
    eval $(opam env)

# Install F*, Rocq, Z3, and ProVerif via OPAM
RUN eval $(opam env) && \
    opam install -y --no-depexts z3 fstar rocq-prover proverif

# Pinned Z3 binary for F* (Makefile --z3version 4.13.3; npm FSTAR_Z3_EXE). OPAM's z3 may be newer.
RUN cd /tmp && \
    wget -q https://github.com/Z3Prover/z3/releases/download/z3-4.13.3/z3-4.13.3-x64-glibc-2.35.zip && \
    unzip -q -o z3-4.13.3-x64-glibc-2.35.zip && \
    cp /tmp/z3-4.13.3-x64-glibc-2.35/bin/z3 /root/.opam/5.1.1/bin/z3-4.13.3 && \
    chmod +x /root/.opam/5.1.1/bin/z3-4.13.3 && \
    /root/.opam/5.1.1/bin/z3-4.13.3 --version && \
    rm -rf /tmp/z3-4.13.3-x64-glibc-2.35 /tmp/z3-4.13.3-x64-glibc-2.35.zip

# Install Lean via elan
ENV ELAN_HOME=/root/.elan \
    PATH=/root/.elan/bin:${PATH}
RUN curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh -s -- -y --default-toolchain leanprover/lean4:v4.28.1 && \
    elan toolchain list && \
    lean --version

WORKDIR /app

# ============================================
# Stage 9: Hax formal verification base
# ============================================
FROM prover-base AS formal-base

ENV RUSTUP_HOME=/root/.rustup \
    CARGO_HOME=/root/.cargo \
    PATH=/root/.opam/5.1.1/bin:/root/.cargo/bin:/root/.elan/bin:/root/.local/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly-2025-02-01 && \
    rustup component add --toolchain nightly-2025-02-01 rustc-dev llvm-tools-preview rust-analysis rust-src rustfmt && \
    rustup default nightly-2025-02-01 && \
    rustc --version && cargo --version

# Install hax from git
RUN eval $(opam env) && \
    git clone https://github.com/hacspec/hax.git /tmp/hax && \
    cd /tmp/hax && \
    ./setup.sh && \
    rm -rf /tmp/hax

# ============================================
# Stage 10: Hax formal verification runner
# ============================================
FROM formal-base AS verification

COPY Cargo.toml Cargo.lock ./
COPY signal-protocol-core ./signal-protocol-core

RUN printf '[toolchain]\nchannel = "nightly-2025-02-01"\ncomponents = ["rustc-dev", "llvm-tools-preview", "rust-analysis", "rust-src", "rustfmt"]\n' > rust-toolchain.toml

WORKDIR /app

CMD ["cargo", "hax", "into", "fstar", "-p", "signal-protocol-core"]

# ============================================
# Stage 11: Aeneas formal verification base
# ============================================
FROM prover-base AS aeneas-base

ENV RUSTUP_HOME=/root/.rustup \
    CARGO_HOME=/root/.cargo \
    PATH=/root/.opam/5.1.1/bin:/root/.cargo/bin:/root/.elan/bin:/root/.local/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly-2026-02-07 && \
    rustup component add --toolchain nightly-2026-02-07 rustc-dev llvm-tools-preview rust-src miri && \
    rustup default nightly-2026-02-07 && \
    rustc --version && cargo --version

# Install Charon (Rust -> LLBC compiler, required by Aeneas)
RUN git clone https://github.com/AeneasVerif/charon.git /tmp/charon && \
    cd /tmp/charon && \
    git checkout ed22146b1cd4d0b578006a58b3299d41ecbe0fd4 && \
    make build-charon-rust && \
    cp bin/charon /root/.cargo/bin/charon && \
    rm -rf /tmp/charon

# Install Aeneas (OCaml: LLBC -> F*/Coq/Lean translator)
RUN eval $(opam env) && \
    opam install -y --no-depexts ppx_deriving visitors easy_logging zarith yojson \
    core_unix ocamlgraph menhir unionFind progress domainslib && \
    git clone https://github.com/AeneasVerif/aeneas.git /tmp/aeneas && \
    cd /tmp/aeneas && \
    git submodule update --init charon && \
    cd charon && git checkout ed22146b1cd4d0b578006a58b3299d41ecbe0fd4 && cd .. && \
    make setup-charon && \
    make build-bin build-lib && \
    mkdir -p /opt/aeneas/bin /opt/aeneas/backends && \
    cp -f src/_build/default/main.exe /opt/aeneas/bin/aeneas && \
    cp -rf backends/fstar /opt/aeneas/backends/fstar && \
    cp -rf backends/coq /opt/aeneas/backends/coq && \
    cp -rf backends/lean /opt/aeneas/backends/lean && \
    ln -sf /opt/aeneas/bin/aeneas /root/.opam/5.1.1/bin/aeneas && \
    rm -rf /tmp/aeneas

# ============================================
# Stage 12: Aeneas formal verification runner
# ============================================
FROM aeneas-base AS aeneas-verification

COPY Cargo.toml Cargo.lock ./
COPY signal-protocol-core ./signal-protocol-core

RUN printf '[toolchain]\nchannel = "nightly-2026-02-07"\ncomponents = ["rustc-dev", "llvm-tools-preview", "rust-src", "miri"]\n' > rust-toolchain.toml

WORKDIR /app

CMD ["bash", "-lc", "cd signal-protocol-core && charon cargo --preset=aeneas && aeneas -backend fstar signal_protocol_core.llbc"]

# ============================================
# Stage 13: ProVerif runner
# ============================================
FROM prover-base AS proverif

COPY formal-proofs ./formal-proofs

WORKDIR /app/formal-proofs

CMD ["./test_proverif.sh"]
