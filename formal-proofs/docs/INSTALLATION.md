# PROVERIF Installation

PROVERIF is needed to run the formal verification models.

## Prerequisites

- OCaml 4.08 or newer
- opam (OCaml package manager)

## Installation

```bash
# Install OCaml and opam on Ubuntu/Debian
sudo apt-get install ocaml opam

# Initialize opam
opam init
eval $(opam env)

# Install PROVERIF
opam install proverif
export PATH="$HOME/.opam/default/bin:$PATH"
```

## Verify Installation

```bash
proverif -help | head -1
```

Should show version 2.05 or higher.

## Running the Proofs

```bash
cd formal-proofs
./test_proverif.sh
```

Or run individual models:

```bash
proverif proverif/x3dh/x3dh_complete.pv
proverif proverif/double_ratchet/double_ratchet_security.pv
```

## Troubleshooting

**"proverif: command not found"**

```bash
export PATH="$HOME/.opam/default/bin:$PATH"
```

**Compilation errors**: Ensure you have PROVERIF 2.05 or newer
