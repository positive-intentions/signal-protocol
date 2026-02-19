module Signal_protocol_wasm.Rust.Utils
#set-options "--fuel 0 --ifuel 1 --z3rlimit 40"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Crypto_common in
  let open Digest.Core_api in
  let open Digest.Core_api.Ct_variable in
  let open Digest.Core_api.Wrapper in
  let open Digest.Digest in
  let open Generic_array in
  let open Hkdf in
  let open Hkdf.Errors in
  let open Hkdf.Sealed in
  let open Js_sys in
  let open Sha2 in
  let open Sha2.Core_api in
  let open Typenum in
  let open Typenum.Bit in
  let open Typenum.Marker_traits in
  let open Typenum.Private in
  let open Typenum.Type_operators in
  let open Typenum.Uint in
  ()

/// Log messages to the browser console for debugging
///
/// Provides visibility into utility operations during development
/// and helps trace data transformations and memory operations.
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

/// Internal function to serialize a public key (native version)
///
/// This is the core serialization logic that can be tested without WASM types.
/// Adds a version byte (0x05) to indicate compressed point format.
let serialize_public_key_internal (public_key: t_Slice u8)
    : Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.String.t_String =
  if (Core_models.Slice.impl__len #u8 public_key <: usize) <>. mk_usize 32
  then
    Core_models.Result.Result_Err
    (Alloc.String.f_to_string #string #FStar.Tactics.Typeclasses.solve "Public key must be 32 bytes"
    )
    <:
    Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.String.t_String
  else
    let serialized:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Alloc.Vec.impl__with_capacity #u8 (mk_usize 33)
    in
    let serialized:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Alloc.Vec.impl_1__push #u8 #Alloc.Alloc.t_Global serialized (mk_u8 5)
    in
    let serialized:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Alloc.Vec.impl_2__extend_from_slice #u8 #Alloc.Alloc.t_Global serialized public_key
    in
    Core_models.Result.Result_Ok serialized
    <:
    Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.String.t_String

/// Internal function to deserialize a public key (native version)
///
/// This is the core deserialization logic that can be tested without WASM types.
/// Removes the version byte and validates the format.
let deserialize_public_key_internal (serialized_key: t_Slice u8)
    : Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.String.t_String =
  if (Core_models.Slice.impl__len #u8 serialized_key <: usize) <>. mk_usize 33
  then
    Core_models.Result.Result_Err
    (Alloc.String.f_to_string #string
        #FStar.Tactics.Typeclasses.solve
        "Serialized key must be 33 bytes")
    <:
    Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.String.t_String
  else
    if (serialized_key.[ mk_usize 0 ] <: u8) <>. mk_u8 5
    then
      Core_models.Result.Result_Err
      (Alloc.String.f_to_string #string #FStar.Tactics.Typeclasses.solve "Invalid key version byte")
      <:
      Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.String.t_String
    else
      Core_models.Result.Result_Ok
      (Alloc.Slice.impl__to_vec #u8
          (serialized_key.[ { Core_models.Ops.Range.f_start = mk_usize 1 }
              <:
              Core_models.Ops.Range.t_RangeFrom usize ]
            <:
            t_Slice u8))
      <:
      Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.String.t_String

/// Internal function for HKDF key derivation (native version)
///
/// This is the core HKDF logic that can be tested without WASM types.
let hkdf_derive_key_internal (input_key salt info: t_Slice u8) (output_length: usize)
    : Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.String.t_String =
  if output_length =. mk_usize 0
  then
    Core_models.Result.Result_Err
    (Alloc.String.f_to_string #string
        #FStar.Tactics.Typeclasses.solve
        "Output length must be greater than 0")
    <:
    Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.String.t_String
  else
    if output_length >. (mk_usize 255 *! mk_usize 32 <: usize)
    then
      Core_models.Result.Result_Err
      (Alloc.String.f_to_string #string
          #FStar.Tactics.Typeclasses.solve
          "Output length too large for HKDF-SHA256")
      <:
      Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.String.t_String
    else
      let hkdf:Hkdf.t_Hkdf
        (Digest.Core_api.Wrapper.t_CoreWrapper
          (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Sha2.Core_api.t_Sha256VarCore
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt
                              (Typenum.Uint.t_UInt
                                  (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                  Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                      Typenum.Bit.t_B0) Typenum.Bit.t_B0)
              Sha2.t_OidSha256))
        (Digest.Core_api.Wrapper.t_CoreWrapper
          (Hmac.Optim.t_HmacCore
            (Digest.Core_api.Wrapper.t_CoreWrapper
              (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Sha2.Core_api.t_Sha256VarCore
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt
                              (Typenum.Uint.t_UInt
                                  (Typenum.Uint.t_UInt
                                      (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                      Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                  Sha2.t_OidSha256)))) =
        if Core_models.Slice.impl__is_empty #u8 salt
        then
          Hkdf.impl_2__new #(Digest.Core_api.Wrapper.t_CoreWrapper
              (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Sha2.Core_api.t_Sha256VarCore
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt
                              (Typenum.Uint.t_UInt
                                  (Typenum.Uint.t_UInt
                                      (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                      Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                  Sha2.t_OidSha256))
            #(Digest.Core_api.Wrapper.t_CoreWrapper
              (Hmac.Optim.t_HmacCore
                (Digest.Core_api.Wrapper.t_CoreWrapper
                  (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Sha2.Core_api.t_Sha256VarCore
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt
                              (Typenum.Uint.t_UInt
                                  (Typenum.Uint.t_UInt
                                      (Typenum.Uint.t_UInt
                                          (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1
                                          ) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                              Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                      Sha2.t_OidSha256))))
            (Core_models.Option.Option_None <: Core_models.Option.t_Option (t_Slice u8))
            input_key
        else
          Hkdf.impl_2__new #(Digest.Core_api.Wrapper.t_CoreWrapper
              (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Sha2.Core_api.t_Sha256VarCore
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt
                              (Typenum.Uint.t_UInt
                                  (Typenum.Uint.t_UInt
                                      (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                      Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                  Sha2.t_OidSha256))
            #(Digest.Core_api.Wrapper.t_CoreWrapper
              (Hmac.Optim.t_HmacCore
                (Digest.Core_api.Wrapper.t_CoreWrapper
                  (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Sha2.Core_api.t_Sha256VarCore
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt
                              (Typenum.Uint.t_UInt
                                  (Typenum.Uint.t_UInt
                                      (Typenum.Uint.t_UInt
                                          (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1
                                          ) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                              Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                      Sha2.t_OidSha256))))
            (Core_models.Option.Option_Some salt <: Core_models.Option.t_Option (t_Slice u8))
            input_key
      in
      let output:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
        Alloc.Vec.from_elem #u8 (mk_u8 0) output_length
      in
      let
      (tmp0: t_Slice u8), (out: Core_models.Result.t_Result Prims.unit Hkdf.Errors.t_InvalidLength)
      =
        Hkdf.impl_2__expand #(Digest.Core_api.Wrapper.t_CoreWrapper
            (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Sha2.Core_api.t_Sha256VarCore
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt
                                    (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                    Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                        Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                Sha2.t_OidSha256))
          #(Digest.Core_api.Wrapper.t_CoreWrapper
            (Hmac.Optim.t_HmacCore
              (Digest.Core_api.Wrapper.t_CoreWrapper
                (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Sha2.Core_api.t_Sha256VarCore
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt
                                    (Typenum.Uint.t_UInt
                                        (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                        Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                            Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Sha2.t_OidSha256))))
          hkdf
          info
          (Alloc.Vec.impl_1__as_slice output <: t_Slice u8)
      in
      let output:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Slice.impl__to_vec tmp0 in
      match
        Core_models.Result.impl__map_err #Prims.unit
          #Hkdf.Errors.t_InvalidLength
          #Alloc.String.t_String
          #(Hkdf.Errors.t_InvalidLength -> Alloc.String.t_String)
          out
          (fun e ->
              let e:Hkdf.Errors.t_InvalidLength = e in
              let args:Hkdf.Errors.t_InvalidLength = e <: Hkdf.Errors.t_InvalidLength in
              let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
                let list =
                  [Core_models.Fmt.Rt.impl__new_display #Hkdf.Errors.t_InvalidLength args]
                in
                FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                Rust_primitives.Hax.array_of_list 1 list
              in
              Core_models.Hint.must_use #Alloc.String.t_String
                (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                        (mk_usize 1)
                        (let list = ["HKDF derivation failed: "] in
                          FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                          Rust_primitives.Hax.array_of_list 1 list)
                        args
                      <:
                      Core_models.Fmt.t_Arguments)
                  <:
                  Alloc.String.t_String))
        <:
        Core_models.Result.t_Result Prims.unit Alloc.String.t_String
      with
      | Core_models.Result.Result_Ok _ ->
        Core_models.Result.Result_Ok output
        <:
        Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.String.t_String
      | Core_models.Result.Result_Err err ->
        Core_models.Result.Result_Err err
        <:
        Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.String.t_String

/// Serialize a public key for transmission or storage
///
/// This function prepares a public key for transmission over a network or
/// storage in a database by adding protocol metadata. In the Signal Protocol,
/// public keys are often serialized with version bytes to ensure compatibility
/// and proper parsing.
///
/// ## Serialization Format
/// - Version byte (0x05): Indicates compressed point format
/// - Key data: The raw 32-byte public key
/// - Total size: 33 bytes
///
/// ## Use Cases
/// - Transmitting public keys in key exchange messages
/// - Storing public keys in databases or key servers
/// - Including public keys in signed prekey bundles
/// - Protocol message headers
///
/// ## Parameters
/// - `public_key`: The 32-byte public key to serialize
///
/// ## Returns
/// A 33-byte serialized key with version prefix
///
/// ## Errors
/// - Returns error if public key is not exactly 32 bytes
///
/// ## Example Usage
/// ```javascript
/// const serialized = serialize_public_key(publicKey);
/// // Send serialized key over network or store in database
/// ```
let serialize_public_key (public_key: Js_sys.t_Uint8Array)
    : Core_models.Result.t_Result Js_sys.t_Uint8Array Wasm_bindgen.t_JsValue =
  let _:Prims.unit = log "Serializing public key for transmission" in
  let key_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Signal_protocol_wasm.Rust.Crypto.uint8_array_to_vec public_key
  in
  match
    serialize_public_key_internal (Alloc.Vec.impl_1__as_slice key_bytes <: t_Slice u8)
    <:
    Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.String.t_String
  with
  | Core_models.Result.Result_Ok serialized ->
    let args:usize = Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global serialized <: usize in
    let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
      let list = [Core_models.Fmt.Rt.impl__new_display #usize args] in
      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
      Rust_primitives.Hax.array_of_list 1 list
    in
    let _:Prims.unit =
      log (Core_models.Ops.Deref.f_deref #Alloc.String.t_String
            #FStar.Tactics.Typeclasses.solve
            (Core_models.Hint.must_use #Alloc.String.t_String
                (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 2)
                        (mk_usize 1)
                        (let list = ["Public key serialized: "; " bytes total"] in
                          FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                          Rust_primitives.Hax.array_of_list 2 list)
                        args
                      <:
                      Core_models.Fmt.t_Arguments)
                  <:
                  Alloc.String.t_String)
              <:
              Alloc.String.t_String)
          <:
          string)
    in
    Core_models.Result.Result_Ok
    (Core_models.Convert.f_from #Js_sys.t_Uint8Array
        #(t_Slice u8)
        #FStar.Tactics.Typeclasses.solve
        (serialized.[ Core_models.Ops.Range.RangeFull <: Core_models.Ops.Range.t_RangeFull ]
          <:
          t_Slice u8))
    <:
    Core_models.Result.t_Result Js_sys.t_Uint8Array Wasm_bindgen.t_JsValue
  | Core_models.Result.Result_Err error ->
    Core_models.Result.Result_Err
    (Wasm_bindgen.impl_JsValue__from_str (Core_models.Ops.Deref.f_deref #Alloc.String.t_String
            #FStar.Tactics.Typeclasses.solve
            error
          <:
          string))
    <:
    Core_models.Result.t_Result Js_sys.t_Uint8Array Wasm_bindgen.t_JsValue

assume
val e_': Prims.unit

unfold
let e_ = e_'

/// Serialize a public key for transmission or storage
///
/// This function prepares a public key for transmission over a network or
/// storage in a database by adding protocol metadata. In the Signal Protocol,
/// public keys are often serialized with version bytes to ensure compatibility
/// and proper parsing.
///
/// ## Serialization Format
/// - Version byte (0x05): Indicates compressed point format
/// - Key data: The raw 32-byte public key
/// - Total size: 33 bytes
///
/// ## Use Cases
/// - Transmitting public keys in key exchange messages
/// - Storing public keys in databases or key servers
/// - Including public keys in signed prekey bundles
/// - Protocol message headers
///
/// ## Parameters
/// - `public_key`: The 32-byte public key to serialize
///
/// ## Returns
/// A 33-byte serialized key with version prefix
///
/// ## Errors
/// - Returns error if public key is not exactly 32 bytes
///
/// ## Example Usage
/// ```javascript
/// const serialized = serialize_public_key(publicKey);
/// // Send serialized key over network or store in database
/// ```
assume
val e___e_ee_wasm_bindgen_generated_serialize_public_key':
    arg0_1_: u32 ->
    arg0_2_: Prims.unit ->
    arg0_3_: Prims.unit ->
    arg0_4_: Prims.unit
  -> Wasm_bindgen.Convert.Traits.t_WasmRet (Core_models.Result.t_Result u32 u32)

unfold
let e___e_ee_wasm_bindgen_generated_serialize_public_key =
  e___e_ee_wasm_bindgen_generated_serialize_public_key'

assume
val e___e_ee_wasm_bindgen_generated_serialize_public_key__e_': Prims.unit

unfold
let e___e_ee_wasm_bindgen_generated_serialize_public_key__e_ =
  e___e_ee_wasm_bindgen_generated_serialize_public_key__e_'

/// Deserialize a public key from its serialized format
///
/// This function extracts a public key from its serialized representation,
/// performing validation checks to ensure the data is well-formed and
/// compatible with the expected protocol version.
///
/// ## Deserialization Process
/// 1. Validate total length (must be 33 bytes)
/// 2. Check version byte (must be 0x05)
/// 3. Extract 32-byte key data
/// 4. Return raw key bytes
///
/// ## Security Considerations
/// - Validates data integrity before processing
/// - Rejects malformed or unexpected formats
/// - Prevents buffer overflow attacks
/// - Ensures protocol compatibility
///
/// ## Parameters
/// - `serialized_key`: The 33-byte serialized key with version prefix
///
/// ## Returns
/// The original 32-byte public key
///
/// ## Errors
/// - Returns error if serialized key is not 33 bytes
/// - Returns error if version byte is not 0x05
/// - Returns error for any malformed input
///
/// ## Example Usage
/// ```javascript
/// const publicKey = deserialize_public_key(receivedData);
/// // Use public key for cryptographic operations
/// ```
let deserialize_public_key (serialized_key: Js_sys.t_Uint8Array)
    : Core_models.Result.t_Result Js_sys.t_Uint8Array Wasm_bindgen.t_JsValue =
  let _:Prims.unit = log "Deserializing public key from transmission format" in
  let serialized_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Signal_protocol_wasm.Rust.Crypto.uint8_array_to_vec serialized_key
  in
  match
    deserialize_public_key_internal (Alloc.Vec.impl_1__as_slice serialized_bytes <: t_Slice u8)
    <:
    Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.String.t_String
  with
  | Core_models.Result.Result_Ok key_data ->
    let args:usize = Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global key_data <: usize in
    let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
      let list = [Core_models.Fmt.Rt.impl__new_display #usize args] in
      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
      Rust_primitives.Hax.array_of_list 1 list
    in
    let _:Prims.unit =
      log (Core_models.Ops.Deref.f_deref #Alloc.String.t_String
            #FStar.Tactics.Typeclasses.solve
            (Core_models.Hint.must_use #Alloc.String.t_String
                (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 2)
                        (mk_usize 1)
                        (let list = ["Public key deserialized successfully: "; " bytes"] in
                          FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                          Rust_primitives.Hax.array_of_list 2 list)
                        args
                      <:
                      Core_models.Fmt.t_Arguments)
                  <:
                  Alloc.String.t_String)
              <:
              Alloc.String.t_String)
          <:
          string)
    in
    Core_models.Result.Result_Ok
    (Core_models.Convert.f_from #Js_sys.t_Uint8Array
        #(t_Slice u8)
        #FStar.Tactics.Typeclasses.solve
        (key_data.[ Core_models.Ops.Range.RangeFull <: Core_models.Ops.Range.t_RangeFull ]
          <:
          t_Slice u8))
    <:
    Core_models.Result.t_Result Js_sys.t_Uint8Array Wasm_bindgen.t_JsValue
  | Core_models.Result.Result_Err error ->
    Core_models.Result.Result_Err
    (Wasm_bindgen.impl_JsValue__from_str (Core_models.Ops.Deref.f_deref #Alloc.String.t_String
            #FStar.Tactics.Typeclasses.solve
            error
          <:
          string))
    <:
    Core_models.Result.t_Result Js_sys.t_Uint8Array Wasm_bindgen.t_JsValue

assume
val e_ee_1': Prims.unit

unfold
let e_ee_1 = e_ee_1'

/// Deserialize a public key from its serialized format
///
/// This function extracts a public key from its serialized representation,
/// performing validation checks to ensure the data is well-formed and
/// compatible with the expected protocol version.
///
/// ## Deserialization Process
/// 1. Validate total length (must be 33 bytes)
/// 2. Check version byte (must be 0x05)
/// 3. Extract 32-byte key data
/// 4. Return raw key bytes
///
/// ## Security Considerations
/// - Validates data integrity before processing
/// - Rejects malformed or unexpected formats
/// - Prevents buffer overflow attacks
/// - Ensures protocol compatibility
///
/// ## Parameters
/// - `serialized_key`: The 33-byte serialized key with version prefix
///
/// ## Returns
/// The original 32-byte public key
///
/// ## Errors
/// - Returns error if serialized key is not 33 bytes
/// - Returns error if version byte is not 0x05
/// - Returns error for any malformed input
///
/// ## Example Usage
/// ```javascript
/// const publicKey = deserialize_public_key(receivedData);
/// // Use public key for cryptographic operations
/// ```
assume
val e_ee_1__e_ee_wasm_bindgen_generated_deserialize_public_key':
    arg0_1_: u32 ->
    arg0_2_: Prims.unit ->
    arg0_3_: Prims.unit ->
    arg0_4_: Prims.unit
  -> Wasm_bindgen.Convert.Traits.t_WasmRet (Core_models.Result.t_Result u32 u32)

unfold
let e_ee_1__e_ee_wasm_bindgen_generated_deserialize_public_key =
  e_ee_1__e_ee_wasm_bindgen_generated_deserialize_public_key'

assume
val e_ee_1__e_ee_wasm_bindgen_generated_deserialize_public_key__e_': Prims.unit

unfold
let e_ee_1__e_ee_wasm_bindgen_generated_deserialize_public_key__e_ =
  e_ee_1__e_ee_wasm_bindgen_generated_deserialize_public_key__e_'

/// Derive cryptographic keys using HKDF (HMAC-based Key Derivation Function)
///
/// HKDF is the standard key derivation function used in the Signal Protocol
/// for expanding shared secrets into specific-purpose keys. It provides
/// cryptographic strength and domain separation for different key uses.
///
/// ## HKDF Algorithm
/// HKDF operates in two phases:
/// 1. **Extract**: Uses HMAC to extract pseudorandom key from input material
/// 2. **Expand**: Expands the pseudorandom key to desired output length
///
/// ## Security Properties
/// - **Entropy preservation**: Maintains entropy from input material
/// - **Domain separation**: Different info strings produce independent keys
/// - **Length flexibility**: Can produce keys of any required length
/// - **Cryptographic strength**: Based on proven HMAC construction
///
/// ## Use Cases
/// - Deriving message keys from shared secrets
/// - Creating separate encryption and authentication keys
/// - Key rotation and forward secrecy
/// - Protocol-specific key derivation
///
/// ## Parameters
/// - `input_key_material`: The source entropy (e.g., ECDH shared secret)
/// - `salt`: Optional salt for additional security (can be empty)
/// - `info`: Context-specific information for domain separation
/// - `output_length`: Desired length of derived key in bytes
///
/// ## Returns
/// A derived key of the specified length
///
/// ## Errors
/// - Returns error if HKDF expansion fails
/// - Returns error for invalid output lengths
///
/// ## Example Usage
/// ```javascript
/// const messageKey = hkdf_derive_key(
///     sharedSecret,
///     salt,
///     new TextEncoder().encode(\"Signal_Message_Key\"),
///     32
/// );
/// ```
let hkdf_derive_key (input_key_material salt info: Js_sys.t_Uint8Array) (output_length: usize)
    : Core_models.Result.t_Result Js_sys.t_Uint8Array Wasm_bindgen.t_JsValue =
  let args:usize = output_length <: usize in
  let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
    let list = [Core_models.Fmt.Rt.impl__new_display #usize args] in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
    Rust_primitives.Hax.array_of_list 1 list
  in
  let _:Prims.unit =
    log (Core_models.Ops.Deref.f_deref #Alloc.String.t_String
          #FStar.Tactics.Typeclasses.solve
          (Core_models.Hint.must_use #Alloc.String.t_String
              (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 2)
                      (mk_usize 1)
                      (let list = ["Deriving key with HKDF: output length "; " bytes"] in
                        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                        Rust_primitives.Hax.array_of_list 2 list)
                      args
                    <:
                    Core_models.Fmt.t_Arguments)
                <:
                Alloc.String.t_String)
            <:
            Alloc.String.t_String)
        <:
        string)
  in
  let ikm:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Signal_protocol_wasm.Rust.Crypto.uint8_array_to_vec input_key_material
  in
  let salt_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Signal_protocol_wasm.Rust.Crypto.uint8_array_to_vec salt
  in
  let info_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Signal_protocol_wasm.Rust.Crypto.uint8_array_to_vec info
  in
  match
    hkdf_derive_key_internal (Alloc.Vec.impl_1__as_slice ikm <: t_Slice u8)
      (Alloc.Vec.impl_1__as_slice salt_bytes <: t_Slice u8)
      (Alloc.Vec.impl_1__as_slice info_bytes <: t_Slice u8)
      output_length
    <:
    Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.String.t_String
  with
  | Core_models.Result.Result_Ok output ->
    let args:usize = Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global output <: usize in
    let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
      let list = [Core_models.Fmt.Rt.impl__new_display #usize args] in
      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
      Rust_primitives.Hax.array_of_list 1 list
    in
    let _:Prims.unit =
      log (Core_models.Ops.Deref.f_deref #Alloc.String.t_String
            #FStar.Tactics.Typeclasses.solve
            (Core_models.Hint.must_use #Alloc.String.t_String
                (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 2)
                        (mk_usize 1)
                        (let list = ["HKDF key derivation completed: "; " bytes generated"] in
                          FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                          Rust_primitives.Hax.array_of_list 2 list)
                        args
                      <:
                      Core_models.Fmt.t_Arguments)
                  <:
                  Alloc.String.t_String)
              <:
              Alloc.String.t_String)
          <:
          string)
    in
    Core_models.Result.Result_Ok
    (Core_models.Convert.f_from #Js_sys.t_Uint8Array
        #(t_Slice u8)
        #FStar.Tactics.Typeclasses.solve
        (output.[ Core_models.Ops.Range.RangeFull <: Core_models.Ops.Range.t_RangeFull ]
          <:
          t_Slice u8))
    <:
    Core_models.Result.t_Result Js_sys.t_Uint8Array Wasm_bindgen.t_JsValue
  | Core_models.Result.Result_Err error ->
    Core_models.Result.Result_Err
    (Wasm_bindgen.impl_JsValue__from_str (Core_models.Ops.Deref.f_deref #Alloc.String.t_String
            #FStar.Tactics.Typeclasses.solve
            error
          <:
          string))
    <:
    Core_models.Result.t_Result Js_sys.t_Uint8Array Wasm_bindgen.t_JsValue

assume
val e_ee_2': Prims.unit

unfold
let e_ee_2 = e_ee_2'

/// Derive cryptographic keys using HKDF (HMAC-based Key Derivation Function)
///
/// HKDF is the standard key derivation function used in the Signal Protocol
/// for expanding shared secrets into specific-purpose keys. It provides
/// cryptographic strength and domain separation for different key uses.
///
/// ## HKDF Algorithm
/// HKDF operates in two phases:
/// 1. **Extract**: Uses HMAC to extract pseudorandom key from input material
/// 2. **Expand**: Expands the pseudorandom key to desired output length
///
/// ## Security Properties
/// - **Entropy preservation**: Maintains entropy from input material
/// - **Domain separation**: Different info strings produce independent keys
/// - **Length flexibility**: Can produce keys of any required length
/// - **Cryptographic strength**: Based on proven HMAC construction
///
/// ## Use Cases
/// - Deriving message keys from shared secrets
/// - Creating separate encryption and authentication keys
/// - Key rotation and forward secrecy
/// - Protocol-specific key derivation
///
/// ## Parameters
/// - `input_key_material`: The source entropy (e.g., ECDH shared secret)
/// - `salt`: Optional salt for additional security (can be empty)
/// - `info`: Context-specific information for domain separation
/// - `output_length`: Desired length of derived key in bytes
///
/// ## Returns
/// A derived key of the specified length
///
/// ## Errors
/// - Returns error if HKDF expansion fails
/// - Returns error for invalid output lengths
///
/// ## Example Usage
/// ```javascript
/// const messageKey = hkdf_derive_key(
///     sharedSecret,
///     salt,
///     new TextEncoder().encode(\"Signal_Message_Key\"),
///     32
/// );
/// ```
assume
val e_ee_2__e_ee_wasm_bindgen_generated_hkdf_derive_key':
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
    arg2_4_: Prims.unit ->
    arg3_1_: u32 ->
    arg3_2_: Prims.unit ->
    arg3_3_: Prims.unit ->
    arg3_4_: Prims.unit
  -> Wasm_bindgen.Convert.Traits.t_WasmRet (Core_models.Result.t_Result u32 u32)

unfold
let e_ee_2__e_ee_wasm_bindgen_generated_hkdf_derive_key =
  e_ee_2__e_ee_wasm_bindgen_generated_hkdf_derive_key'

assume
val e_ee_2__e_ee_wasm_bindgen_generated_hkdf_derive_key__e_': Prims.unit

unfold
let e_ee_2__e_ee_wasm_bindgen_generated_hkdf_derive_key__e_ =
  e_ee_2__e_ee_wasm_bindgen_generated_hkdf_derive_key__e_'

/// Free memory associated with a KeyPair (placeholder for manual memory management)
///
/// In Rust, memory management is automatic through RAII (Resource Acquisition Is Initialization).
/// This function exists for API compatibility with other implementations that might require
/// explicit memory management (e.g., C implementations).
///
/// ## Memory Management in Rust
/// - Rust automatically deallocates memory when variables go out of scope
/// - No manual memory management is typically required
/// - This function serves as a no-op placeholder for API compatibility
///
/// ## Use Cases
/// - API compatibility with C-based implementations
/// - Explicit documentation of cleanup points
/// - Future integration with custom allocators
/// - Testing memory management flows
///
/// ## Parameters
/// - `_keypair`: The KeyPair to \"free\" (parameter is ignored)
///
/// ## Example Usage
/// ```javascript
/// // Optional explicit cleanup (not required in Rust/WASM)
/// free_keypair(keyPair);
/// ```
let free_keypair (e_keypair: Signal_protocol_wasm.Rust.Types.t_KeyPair) : Prims.unit =
  let _:Prims.unit = log "KeyPair memory cleanup requested (automatic in Rust)" in
  ()

assume
val e_ee_3': Prims.unit

unfold
let e_ee_3 = e_ee_3'

/// Free memory associated with a KeyPair (placeholder for manual memory management)
///
/// In Rust, memory management is automatic through RAII (Resource Acquisition Is Initialization).
/// This function exists for API compatibility with other implementations that might require
/// explicit memory management (e.g., C implementations).
///
/// ## Memory Management in Rust
/// - Rust automatically deallocates memory when variables go out of scope
/// - No manual memory management is typically required
/// - This function serves as a no-op placeholder for API compatibility
///
/// ## Use Cases
/// - API compatibility with C-based implementations
/// - Explicit documentation of cleanup points
/// - Future integration with custom allocators
/// - Testing memory management flows
///
/// ## Parameters
/// - `_keypair`: The KeyPair to \"free\" (parameter is ignored)
///
/// ## Example Usage
/// ```javascript
/// // Optional explicit cleanup (not required in Rust/WASM)
/// free_keypair(keyPair);
/// ```
assume
val e_ee_3__e_ee_wasm_bindgen_generated_free_keypair':
    arg0_1_: u32 ->
    arg0_2_: Prims.unit ->
    arg0_3_: Prims.unit ->
    arg0_4_: Prims.unit
  -> Wasm_bindgen.Convert.Traits.t_WasmRet Prims.unit

unfold
let e_ee_3__e_ee_wasm_bindgen_generated_free_keypair =
  e_ee_3__e_ee_wasm_bindgen_generated_free_keypair'

assume
val e_ee_3__e_ee_wasm_bindgen_generated_free_keypair__e_': Prims.unit

unfold
let e_ee_3__e_ee_wasm_bindgen_generated_free_keypair__e_ =
  e_ee_3__e_ee_wasm_bindgen_generated_free_keypair__e_'

/// Free memory associated with a buffer (placeholder for manual memory management)
///
/// Similar to `free_keypair`, this function exists for API compatibility.
/// Rust\'s automatic memory management handles buffer cleanup automatically
/// when the buffer goes out of scope.
///
/// ## Buffer Management
/// - Uint8Array data is automatically managed by the JavaScript engine
/// - Rust Vec<u8> data is automatically deallocated when dropped
/// - No manual intervention is required in typical usage
///
/// ## Parameters
/// - `_buffer`: The buffer to \"free\" (parameter is ignored)
///
/// ## Example Usage
/// ```javascript
/// // Optional explicit cleanup (not required in Rust/WASM)
/// free_buffer(buffer);
/// ```
let free_buffer (e_buffer: Js_sys.t_Uint8Array) : Prims.unit =
  let _:Prims.unit = log "Buffer memory cleanup requested (automatic in Rust/WASM)" in
  ()

assume
val e_ee_4': Prims.unit

unfold
let e_ee_4 = e_ee_4'

/// Free memory associated with a buffer (placeholder for manual memory management)
///
/// Similar to `free_keypair`, this function exists for API compatibility.
/// Rust\'s automatic memory management handles buffer cleanup automatically
/// when the buffer goes out of scope.
///
/// ## Buffer Management
/// - Uint8Array data is automatically managed by the JavaScript engine
/// - Rust Vec<u8> data is automatically deallocated when dropped
/// - No manual intervention is required in typical usage
///
/// ## Parameters
/// - `_buffer`: The buffer to \"free\" (parameter is ignored)
///
/// ## Example Usage
/// ```javascript
/// // Optional explicit cleanup (not required in Rust/WASM)
/// free_buffer(buffer);
/// ```
assume
val e_ee_4__e_ee_wasm_bindgen_generated_free_buffer':
    arg0_1_: u32 ->
    arg0_2_: Prims.unit ->
    arg0_3_: Prims.unit ->
    arg0_4_: Prims.unit
  -> Wasm_bindgen.Convert.Traits.t_WasmRet Prims.unit

unfold
let e_ee_4__e_ee_wasm_bindgen_generated_free_buffer =
  e_ee_4__e_ee_wasm_bindgen_generated_free_buffer'

assume
val e_ee_4__e_ee_wasm_bindgen_generated_free_buffer__e_': Prims.unit

unfold
let e_ee_4__e_ee_wasm_bindgen_generated_free_buffer__e_ =
  e_ee_4__e_ee_wasm_bindgen_generated_free_buffer__e_'
