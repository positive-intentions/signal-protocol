module Signal_protocol_wasm.Rust.Crypto
#set-options "--fuel 0 --ifuel 1 --z3rlimit 40"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Js_sys in
  let open Signal_protocol_core.Error in
  ()

/// Utility function to convert JavaScript Uint8Array to Rust Vec<u8>
/// This helper function bridges the gap between JavaScript typed arrays
/// and Rust vectors, enabling seamless data transfer across the WASM boundary.
let uint8_array_to_vec (arr: Js_sys.t_Uint8Array) : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  Js_sys.impl_Uint8Array__to_vec arr

/// Log messages to the browser console for debugging
/// **SECURITY NOTE**: Only logs non-sensitive operational information.
/// Never logs keys, secrets, or other cryptographic material.
let log (s: string) : Prims.unit =
  let args:string = s <: string in
  let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
    let list = [Core_models.Fmt.Rt.impl__new_display #string args] in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
    Rust_primitives.Hax.array_of_list 1 list
  in
  let _:Prims.unit =
    Std.Io.Stdio.e_eprint (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 2)
          (mk_usize 1)
          (let list = [""; "\n"] in
            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
            Rust_primitives.Hax.array_of_list 2 list)
          args
        <:
        Core_models.Fmt.t_Arguments)
  in
  let _:Prims.unit = () in
  ()

/// Validate that a public key is a valid X25519 point - delegates to core
let validate_x25519_public_key (public_key: t_Slice u8)
    : Core_models.Result.t_Result Prims.unit Signal_protocol_core.Error.t_SignalError =
  Signal_protocol_core.Crypto.validate_x25519_public_key public_key

/// Perform X25519 ECDH - delegates to core
let x25519_ecdh (private_key public_key: t_Slice u8)
    : Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      Signal_protocol_core.Error.t_SignalError =
  Signal_protocol_core.Crypto.x25519_ecdh private_key public_key

/// Legacy name for ECDH - kept for compatibility
/// Returns Result for panic-free operation. Callers should use ? or .unwrap().
let simple_ecdh (private_key public_key: t_Slice u8)
    : Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      Signal_protocol_core.Error.t_SignalError =
  Signal_protocol_core.Crypto.simple_ecdh private_key public_key

/// Internal function to sign data - delegates to core
let sign_data_internal (private_key data: t_Slice u8)
    : Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      Signal_protocol_core.Error.t_SignalError =
  Signal_protocol_core.Crypto.sign_data_internal private_key data

/// Internal function to verify signature - delegates to core
let verify_signature_internal (public_key signature data: t_Slice u8)
    : Core_models.Result.t_Result bool Signal_protocol_core.Error.t_SignalError =
  Signal_protocol_core.Crypto.verify_signature_internal public_key signature data

/// Sign data using Ed25519 digital signature algorithm
/// Creates a cryptographically secure digital signature that proves the data
/// was signed by the holder of the corresponding Ed25519 private key.
/// The signature can be verified by anyone who has the public key.
/// ## Implementation
/// Uses Ed25519 (Edwards-curve Digital Signature Algorithm) which provides:
/// - 128-bit security level
/// - Deterministic signatures (same input = same signature)
/// - Small signature size (64 bytes)
/// - Fast verification
/// ## Usage Example
/// ```javascript
/// const signature = sign_data(privateKey, message);
/// const isValid = verify_signature(publicKey, signature, message);
/// ```
/// ## Parameters
/// - `private_key`: The signer\'s Ed25519 private key as Uint8Array (must be 32 bytes)
/// - `data`: The data to sign as Uint8Array
/// ## Returns
/// A Uint8Array containing the 64-byte Ed25519 signature
/// ## Errors
/// - Returns error if private key is not exactly 32 bytes
/// - Returns error if signing operation fails
let sign_data (private_key data: Js_sys.t_Uint8Array)
    : Core_models.Result.t_Result Js_sys.t_Uint8Array Wasm_bindgen.t_JsValue =
  let _:Prims.unit = log "Signing data with Ed25519" in
  let private_key_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = uint8_array_to_vec private_key in
  let data_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = uint8_array_to_vec data in
  match
    sign_data_internal (Alloc.Vec.impl_1__as_slice private_key_bytes <: t_Slice u8)
      (Alloc.Vec.impl_1__as_slice data_bytes <: t_Slice u8)
    <:
    Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      Signal_protocol_core.Error.t_SignalError
  with
  | Core_models.Result.Result_Ok signature_bytes ->
    Core_models.Result.Result_Ok
    (Core_models.Convert.f_from #Js_sys.t_Uint8Array
        #(t_Slice u8)
        #FStar.Tactics.Typeclasses.solve
        (Alloc.Vec.impl_1__as_slice #u8 #Alloc.Alloc.t_Global signature_bytes <: t_Slice u8))
    <:
    Core_models.Result.t_Result Js_sys.t_Uint8Array Wasm_bindgen.t_JsValue
  | Core_models.Result.Result_Err e ->
    Core_models.Result.Result_Err
    (Wasm_bindgen.impl_JsValue__from_str (Core_models.Ops.Deref.f_deref #Alloc.String.t_String
            #FStar.Tactics.Typeclasses.solve
            (Alloc.String.f_to_string #Signal_protocol_core.Error.t_SignalError
                #FStar.Tactics.Typeclasses.solve
                e
              <:
              Alloc.String.t_String)
          <:
          string))
    <:
    Core_models.Result.t_Result Js_sys.t_Uint8Array Wasm_bindgen.t_JsValue

assume
val e_': Prims.unit

unfold
let e_ = e_'

/// Sign data using Ed25519 digital signature algorithm
/// Creates a cryptographically secure digital signature that proves the data
/// was signed by the holder of the corresponding Ed25519 private key.
/// The signature can be verified by anyone who has the public key.
/// ## Implementation
/// Uses Ed25519 (Edwards-curve Digital Signature Algorithm) which provides:
/// - 128-bit security level
/// - Deterministic signatures (same input = same signature)
/// - Small signature size (64 bytes)
/// - Fast verification
/// ## Usage Example
/// ```javascript
/// const signature = sign_data(privateKey, message);
/// const isValid = verify_signature(publicKey, signature, message);
/// ```
/// ## Parameters
/// - `private_key`: The signer\'s Ed25519 private key as Uint8Array (must be 32 bytes)
/// - `data`: The data to sign as Uint8Array
/// ## Returns
/// A Uint8Array containing the 64-byte Ed25519 signature
/// ## Errors
/// - Returns error if private key is not exactly 32 bytes
/// - Returns error if signing operation fails
assume
val e___e_ee_wasm_bindgen_generated_sign_data':
    arg0_1_: u32 ->
    arg0_2_: Prims.unit ->
    arg0_3_: Prims.unit ->
    arg0_4_: Prims.unit ->
    arg1_1_: u32 ->
    arg1_2_: Prims.unit ->
    arg1_3_: Prims.unit ->
    arg1_4_: Prims.unit
  -> Wasm_bindgen.Convert.Traits.t_WasmRet (Core_models.Result.t_Result u32 u32)

unfold
let e___e_ee_wasm_bindgen_generated_sign_data = e___e_ee_wasm_bindgen_generated_sign_data'

assume
val e___e_ee_wasm_bindgen_generated_sign_data__e_': Prims.unit

unfold
let e___e_ee_wasm_bindgen_generated_sign_data__e_ = e___e_ee_wasm_bindgen_generated_sign_data__e_'

/// Verify an Ed25519 digital signature
/// Verifies that a signature was created by the holder of the private key
/// corresponding to the given Ed25519 public key. This ensures message
/// authenticity and integrity through elliptic curve cryptography.
/// ## Security Properties
/// - **Unforgeability**: Cannot create valid signatures without private key
/// - **Non-repudiation**: Signer cannot deny creating the signature
/// - **Integrity**: Any modification to data invalidates the signature
/// - **Constant-time**: Verification takes same time regardless of validity
/// ## Usage Example
/// ```javascript
/// const isValid = verify_signature(publicKey, signature, originalMessage);
/// if (isValid) {
///     console.log(\"Signature is valid!\");
/// }
/// ```
/// ## Parameters
/// - `public_key`: The signer\'s Ed25519 public key as Uint8Array (must be 32 bytes)
/// - `signature`: The Ed25519 signature to verify as Uint8Array (must be 64 bytes)
/// - `data`: The original signed data as Uint8Array
/// ## Returns
/// `true` if the signature is valid, `false` otherwise
/// ## Errors
/// - Returns error if public key is not exactly 32 bytes
/// - Returns error if signature is not exactly 64 bytes
/// - Returns error if key format is invalid
let verify_signature (public_key signature data: Js_sys.t_Uint8Array)
    : Core_models.Result.t_Result bool Wasm_bindgen.t_JsValue =
  let _:Prims.unit = log "Verifying signature with Ed25519" in
  let public_key_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = uint8_array_to_vec public_key in
  let signature_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = uint8_array_to_vec signature in
  let data_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = uint8_array_to_vec data in
  match
    verify_signature_internal (Alloc.Vec.impl_1__as_slice public_key_bytes <: t_Slice u8)
      (Alloc.Vec.impl_1__as_slice signature_bytes <: t_Slice u8)
      (Alloc.Vec.impl_1__as_slice data_bytes <: t_Slice u8)
    <:
    Core_models.Result.t_Result bool Signal_protocol_core.Error.t_SignalError
  with
  | Core_models.Result.Result_Ok is_valid ->
    Core_models.Result.Result_Ok is_valid <: Core_models.Result.t_Result bool Wasm_bindgen.t_JsValue
  | Core_models.Result.Result_Err e ->
    Core_models.Result.Result_Err
    (Wasm_bindgen.impl_JsValue__from_str (Core_models.Ops.Deref.f_deref #Alloc.String.t_String
            #FStar.Tactics.Typeclasses.solve
            (Alloc.String.f_to_string #Signal_protocol_core.Error.t_SignalError
                #FStar.Tactics.Typeclasses.solve
                e
              <:
              Alloc.String.t_String)
          <:
          string))
    <:
    Core_models.Result.t_Result bool Wasm_bindgen.t_JsValue

assume
val e_ee_1': Prims.unit

unfold
let e_ee_1 = e_ee_1'

/// Verify an Ed25519 digital signature
/// Verifies that a signature was created by the holder of the private key
/// corresponding to the given Ed25519 public key. This ensures message
/// authenticity and integrity through elliptic curve cryptography.
/// ## Security Properties
/// - **Unforgeability**: Cannot create valid signatures without private key
/// - **Non-repudiation**: Signer cannot deny creating the signature
/// - **Integrity**: Any modification to data invalidates the signature
/// - **Constant-time**: Verification takes same time regardless of validity
/// ## Usage Example
/// ```javascript
/// const isValid = verify_signature(publicKey, signature, originalMessage);
/// if (isValid) {
///     console.log(\"Signature is valid!\");
/// }
/// ```
/// ## Parameters
/// - `public_key`: The signer\'s Ed25519 public key as Uint8Array (must be 32 bytes)
/// - `signature`: The Ed25519 signature to verify as Uint8Array (must be 64 bytes)
/// - `data`: The original signed data as Uint8Array
/// ## Returns
/// `true` if the signature is valid, `false` otherwise
/// ## Errors
/// - Returns error if public key is not exactly 32 bytes
/// - Returns error if signature is not exactly 64 bytes
/// - Returns error if key format is invalid
assume
val e_ee_1__e_ee_wasm_bindgen_generated_verify_signature':
    arg0_1_: u32 ->
    arg0_2_: Prims.unit ->
    arg0_3_: Prims.unit ->
    arg0_4_: Prims.unit ->
    arg1_1_: u32 ->
    arg1_2_: Prims.unit ->
    arg1_3_: Prims.unit ->
    arg1_4_: Prims.unit ->
    arg2_1_: u32 ->
    arg2_2_: Prims.unit ->
    arg2_3_: Prims.unit ->
    arg2_4_: Prims.unit
  -> Wasm_bindgen.Convert.Traits.t_WasmRet (Core_models.Result.t_Result u32 u32)

unfold
let e_ee_1__e_ee_wasm_bindgen_generated_verify_signature =
  e_ee_1__e_ee_wasm_bindgen_generated_verify_signature'

assume
val e_ee_1__e_ee_wasm_bindgen_generated_verify_signature__e_': Prims.unit

unfold
let e_ee_1__e_ee_wasm_bindgen_generated_verify_signature__e_ =
  e_ee_1__e_ee_wasm_bindgen_generated_verify_signature__e_'

/// Internal signature functions for compatibility (deprecated - use Ed25519 above)
/// These functions are kept for backward compatibility but should not be used
/// in new code. They previously implemented fake signatures using HMAC.
let simple_sign (e_private_key e_data: t_Slice u8) : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  Rust_primitives.Hax.never_to_any (Core_models.Panicking.panic_fmt (Core_models.Fmt.Rt.impl_1__new_const
            (mk_usize 1)
            (let list = ["simple_sign is deprecated - use Ed25519 sign_data instead"] in
              FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
              Rust_primitives.Hax.array_of_list 1 list)
          <:
          Core_models.Fmt.t_Arguments)
      <:
      Rust_primitives.Hax.t_Never)

let simple_verify (e_public_key e_signature e_data: t_Slice u8) : bool =
  Rust_primitives.Hax.never_to_any (Core_models.Panicking.panic_fmt (Core_models.Fmt.Rt.impl_1__new_const
            (mk_usize 1)
            (let list = ["simple_verify is deprecated - use Ed25519 verify_signature instead"] in
              FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
              Rust_primitives.Hax.array_of_list 1 list)
          <:
          Core_models.Fmt.t_Arguments)
      <:
      Rust_primitives.Hax.t_Never)
