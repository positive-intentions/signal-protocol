# HKDF Constants Reference

This document lists the HKDF constants used in the implementation and formal verification models.

## HKDF Function Signature

### Rust Implementation

The Rust implementation uses the HKDF pattern from the `hkdf` crate:

```rust
let hkdf = Hkdf::<Sha256>::new(Some(salt), input_keying_material);
hkdf.expand(info, &mut output);
```

### ProVerif Modeling

ProVerif models this as a 3-argument function:

```proverif
fun hkdf(salt, input_keying_material, info): bitstring.
```

This abstracts the two-step Rust pattern (`new` then `expand`) into a single ProVerif function call.

## X3DH

### Constants

```
Salt: "Signal_X3DH_Salt"
Info: "Signal_X3DH_Key_Derivation"
```

These are used in `src/rust/x3dh.rs` to derive the final shared secret from concatenated DH outputs.

### ProVerif Signature

```proverif
let salt = hkdf_salt_x3dh() in
let info = hkdf_info_x3dh() in
let root = hkdf(salt, combined_dh_output, info) in
```

## Double Ratchet

### Info Strings

```
Signal_DoubleRatchet_ChainKey
Signal_DoubleRatchet_MessageKey
```

### Salts

```
Signal_DH_Ratchet        // DH ratchet steps (lines 335, 414)
Signal_Initial_Chain     // Initial chain derivation (lines 358, 608)
Signal_Message_Salt      // Message key derivation (line 264)
Signal_Chain_Salt        // Chain key advancement (line 289)
```

### AAD Format

Additional authenticated data for message encryption (lines 648-652):

```
DH_public_key || message_number || previous_chain_length
```

### ProVerif Signature

```proverif
// Chain key derivation
let chain_new = hkdf(hkdf_info_chain_key(), root_new, hkdf_info_chain_key()) in

// Message key derivation
let info_msg = hkdf_info_message_key() in
let msg_key = hkdf(info_msg, chain_new, info_msg) in
```

## Quick Reference

| Use Case           | Salt                 | Info String                     | ProVerif Pattern                        |
| ------------------ | -------------------- | ------------------------------- | --------------------------------------- |
| X3DH handshake     | Signal_X3DH_Salt     | Signal_X3DH_Key_Derivation      | hkdf(salt, dh_concat, info)             |
| DH ratchet         | Signal_DH_Ratchet    | Signal_DoubleRatchet_ChainKey   | hkdf(salt, dh_output, info)             |
| Initial chain key  | Signal_Initial_Chain | Signal_DoubleRatchet_ChainKey   | hkdf(salt, root_key, info)              |
| Derive message key | Signal_Message_Salt  | Signal_DoubleRatchet_MessageKey | hkdf(salt, chain_key, info)             |
| Advance chain key  | Signal_Chain_Salt    | Signal_DoubleRatchet_ChainKey   | hkdf(info, chain_key, info) (salt=info) |

## Implementation Locations

- `src/rust/x3dh.rs` - X3DH constants (lines 60-65)
- `src/rust/double_ratchet.rs` - Double Ratchet constants and AAD

## Formal Verification

The ProVerif models use functions to represent these constant values:

```proverif
fun hkdf_salt_x3dh(): bitstring.
fun hkdf_info_x3dh(): bitstring.
fun hkdf_salt_dh_ratchet(): bitstring.
fun hkdf_info_chain_key(): bitstring.
fun hkdf_info_message_key(): bitstring.
```

Due to ProVerif syntax limitations, these are modeled as functions rather than literal string constants. All ProVerif models consistently use the 3-argument `hkdf(salt, ikm, info)` signature to match the Rust implementation pattern.
