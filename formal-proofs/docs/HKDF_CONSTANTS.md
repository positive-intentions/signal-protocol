# Signal Protocol Formal Verification - Implementation Constants Reference

This document contains the HKDF and other constants from the implementation that should be modeled in the formal verification.

## X3DH Constants

From `src/rust/x3dh.rs`:

### HKDF Constants

```rust
// Lines 60-61
let salt = b"Signal_X3DH_Salt";
let info = b"Signal_X3DH_Key_Derivation";
```

**Purpose**: Derive the final shared secret from concatenated DH outputs.

**CryptoVerif Modeling Note**:

- Constant declarations (`const X = Y.`) cause syntax errors in CryptoVerif
- Current workarounds under investigation:
  - Use variable names for constants without explicit values
  - Model HKDF as oracle/function without constants
  - Use string literals inline (syntax to be verified)

## Double Ratchet Constants

From `src/rust/double_ratchet.rs`:

### HKDF Info Strings

```rust
// Lines 43-44
const HKDF_INFO_CHAIN_KEY: &[u8] = b"Signal_DoubleRatchet_ChainKey";
const HKDF_INFO_MESSAGE_KEY: &[u8] = b"Signal_DoubleRatchet_MessageKey";
```

### HKDF Salts

```rust
// Line 358 - DH Ratchet salt
let hkdf = Hkdf::<Sha256>::new(Some(b"Signal_DH_Ratchet"), &original_root_key);

// Line 60 (in DH ratchet initialization) - Initial chain salt
let hkdf = Hkdf::<Sha256>::new(Some(b"Signal_Initial_Chain"), &state.root_key);
```

### AAD Format

```rust
// Lines 648-652 - Additional Authenticated Data format
// Format: DH_public_key || message_number || previous_chain_length
let mut aad = Vec::new();
aad.extend_from_slice(&sending_dh_keypair.public_key);
aad.extend_from_slice(&state.sending_message_number.to_be_bytes());
aad.extend_from_slice(&state.previous_chain_length.to_be_bytes());
```

## HKDF Constant Summary Table

| Protocol Component           | Salt                   | Info                              | Purpose                                                    |
| ---------------------------- | ---------------------- | --------------------------------- | ---------------------------------------------------------- |
| X3DH                         | `Signal_X3DH_Salt`     | `Signal_X3DH_Key_Derivation`      | Derive X3DH shared secret from DH concatenation            |
| Double Ratchet (DH Ratchet)  | `Signal_DH_Ratchet`    | `Signal_DoubleRatchet_ChainKey`   | Derive new root key and receiving chain key from DH output |
| Double Ratchet (Chain Key)   | Uses root key as IKE   | `Signal_DoubleRatchet_ChainKey`   | Derive next chain key from current chain key               |
| Double Ratchet (Message Key) | Uses chain key as IKE  | `Signal_DoubleRatchet_MessageKey` | Derive message key from chain key                          |
| Double Ratchet (Initial)     | `Signal_Initial_Chain` | `Signal_DoubleRatchet_ChainKey`   | Derive initial receiving chain key from root key           |

## Modeling Strategy

### Option 1: Constants as Named Primitives

```cryptoVerif
(* Instead of: const salt = b"Signal_X3DH_Salt" *)
(* Use named functions that represent the constant value *)

fun hkdf_salt_x3dh(): bitstring.
fun hkdf_info_x3dh(): bitstring.
fun hkdf_salt_dh_ratchet(): bitstring.
```

### Option 2: Inline Without Values

```cryptoVerif
(* Model HKDF with input parameter but no explicit values *)

fun hkdf_extract(bitstring, bitstring): bitstring.
(* Call with: hkdf_extract(hkdf_salt_x3dh(), dh_output) *)
```

### Option 3: Oracle Model

```cryptoVerif
oracle HKDF_EXTRACT(bitstring salt, bitstring ikm): bitstring =
  salt, ikm
```

## Current Implementation Status

✅ Constants documented from source code
⏸ CryptoVerif syntax for constant values causing errors
📝 Alternative modeling approaches identified
🔄 Testing required for each approach

## Next Steps for Constants Modeling

1. Test Option 1: Named functions for constants
2. Test Option 2: Oracle model
3. Verify which approach compiles and provides desired proofs
4. Update x3dh_working.cv to use winner approach
5. Document final pattern in FORMAL_PROOF_STATUS.md
