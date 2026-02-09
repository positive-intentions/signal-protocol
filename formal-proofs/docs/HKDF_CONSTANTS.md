# HKDF Constants Reference

This document lists the HKDF constants used in the implementation and formal verification models.

## X3DH

### Constants

```
Salt: "Signal_X3DH_Salt"
Info: "Signal_X3DH_Key_Derivation"
```

These are used in `src/rust/x3dh.rs` to derive the final shared secret from concatenated DH outputs.

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

## Quick Reference

| Use Case           | Salt                 | Info String                     |
| ------------------ | -------------------- | ------------------------------- |
| X3DH handshake     | Signal_X3DH_Salt     | Signal_X3DH_Key_Derivation      |
| DH ratchet         | Signal_DH_Ratchet    | Signal_DoubleRatchet_ChainKey   |
| Initial chain key  | Signal_Initial_Chain | Signal_DoubleRatchet_ChainKey   |
| Derive message key | Signal_Message_Salt  | Signal_DoubleRatchet_MessageKey |
| Advance chain key  | Signal_Chain_Salt    | Signal_DoubleRatchet_ChainKey   |

## Implementation Locations

- `src/rust/x3dh.rs` - X3DH constants
- `src/rust/double_ratchet.rs` - Double Ratchet constants and AAD

## Formal Verification

The ProVerif models use functions to represent these constant values:

```
fun hkdf_salt_x3dh(): bitstring.
fun hkdf_info_x3dh(): bitstring.
fun hkdf_salt_dh_ratchet(): bitstring.
fun hkdf_info_chain_key(): bitstring.
```

Due to ProVerif syntax limitations, these are modeled as functions rather than literal string constants.
