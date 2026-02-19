module Signal_protocol_wasm.Rust.X3dh
#set-options "--fuel 0 --ifuel 1 --z3rlimit 40"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Signal_protocol_core.Error in
  ()

/// Log messages to the browser console for debugging
///
/// Helps trace the X3DH protocol execution and debug issues
/// during key exchange operations.
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

/// Internal function to initiate X3DH key exchange - delegates to core
let x3dh_initiate_internal
      (alice_identity_private alice_ephemeral_private bob_identity_public bob_signed_prekey_public:
          t_Slice u8)
      (bob_one_time_prekey_public: Core_models.Option.t_Option (t_Slice u8))
    : Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_X3DHResult
      Signal_protocol_core.Error.t_SignalError =
  match
    Signal_protocol_core.X3dh.x3dh_initiate_internal alice_identity_private
      alice_ephemeral_private
      bob_identity_public
      bob_signed_prekey_public
      bob_one_time_prekey_public
    <:
    Core_models.Result.t_Result Signal_protocol_core.Types.t_X3DHResult
      Signal_protocol_core.Error.t_SignalError
  with
  | Core_models.Result.Result_Ok core_result ->
    Core_models.Result.Result_Ok
    ({
        Signal_protocol_wasm.Rust.Types.f_shared_secret
        =
        core_result.Signal_protocol_core.Types.f_shared_secret;
        Signal_protocol_wasm.Rust.Types.f_associated_data
        =
        core_result.Signal_protocol_core.Types.f_associated_data
      }
      <:
      Signal_protocol_wasm.Rust.Types.t_X3DHResult)
    <:
    Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_X3DHResult
      Signal_protocol_core.Error.t_SignalError
  | Core_models.Result.Result_Err err ->
    Core_models.Result.Result_Err err
    <:
    Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_X3DHResult
      Signal_protocol_core.Error.t_SignalError

/// Internal function to respond to X3DH key exchange - delegates to core
let x3dh_respond_internal
      (bob_identity_private bob_signed_prekey_private: t_Slice u8)
      (bob_one_time_prekey_private: Core_models.Option.t_Option (t_Slice u8))
      (alice_identity_public alice_ephemeral_public: t_Slice u8)
    : Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_X3DHResult
      Signal_protocol_core.Error.t_SignalError =
  match
    Signal_protocol_core.X3dh.x3dh_respond_internal bob_identity_private
      bob_signed_prekey_private
      bob_one_time_prekey_private
      alice_identity_public
      alice_ephemeral_public
    <:
    Core_models.Result.t_Result Signal_protocol_core.Types.t_X3DHResult
      Signal_protocol_core.Error.t_SignalError
  with
  | Core_models.Result.Result_Ok core_result ->
    Core_models.Result.Result_Ok
    ({
        Signal_protocol_wasm.Rust.Types.f_shared_secret
        =
        core_result.Signal_protocol_core.Types.f_shared_secret;
        Signal_protocol_wasm.Rust.Types.f_associated_data
        =
        core_result.Signal_protocol_core.Types.f_associated_data
      }
      <:
      Signal_protocol_wasm.Rust.Types.t_X3DHResult)
    <:
    Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_X3DHResult
      Signal_protocol_core.Error.t_SignalError
  | Core_models.Result.Result_Err err ->
    Core_models.Result.Result_Err err
    <:
    Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_X3DHResult
      Signal_protocol_core.Error.t_SignalError

/// Initiate X3DH key exchange (Alice\'s side)
///
/// This function performs the X3DH key agreement from the initiator\'s perspective.
/// Alice combines her keys with Bob\'s prekeys to compute a shared secret that
/// both parties can independently derive.
///
/// ## X3DH Protocol Overview
/// The X3DH protocol performs multiple Diffie-Hellman computations:
/// 1. DH1: Alice_Identity_Private × Bob_SignedPrekey_Public
/// 2. DH2: Alice_Ephemeral_Private × Bob_Identity_Public
/// 3. DH3: Alice_Ephemeral_Private × Bob_SignedPrekey_Public
/// 4. DH4: Alice_Ephemeral_Private × Bob_OneTimePrekey_Public (optional)
///
/// The results are concatenated and fed into HKDF to derive the final shared secret.
///
/// ## Security Properties
/// - **Forward Secrecy**: Compromise of long-term keys doesn\'t affect past sessions
/// - **Authentication**: Both parties prove their identity through key ownership
/// - **Asynchronous**: Bob doesn\'t need to be online during key exchange
/// - **Deniability**: No long-term proof of participation in conversations
///
/// ## Parameters
/// - `alice_identity_private`: Alice\'s long-term identity private key (32 bytes)
/// - `alice_ephemeral_private`: Alice\'s session-specific ephemeral private key (32 bytes)
/// - `bob_identity_public`: Bob\'s identity public key (32 bytes)
/// - `bob_signed_prekey_public`: Bob\'s signed prekey public key (32 bytes)
/// - `bob_one_time_prekey_public`: Optional one-time prekey for additional forward secrecy
///
/// ## Returns
/// An `X3DHResult` containing the shared secret and associated data
///
/// ## Example Usage
/// ```rust
/// let result = x3dh_initiate(
///     &alice_identity_private,
///     &alice_ephemeral_private,
///     &bob_identity_public,
///     &bob_signed_prekey_public,
///     Some(bob_one_time_prekey_public)
/// )?;
/// let shared_secret = result.shared_secret();
/// ```
let x3dh_initiate
      (alice_identity_private alice_ephemeral_private bob_identity_public bob_signed_prekey_public:
          Js_sys.t_Uint8Array)
      (bob_one_time_prekey_public: Core_models.Option.t_Option Js_sys.t_Uint8Array)
    : Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_X3DHResult
      Wasm_bindgen.t_JsValue =
  let _:Prims.unit = log "Initiating X3DH key exchange (Alice side)" in
  let alice_identity_private_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Signal_protocol_wasm.Rust.Crypto.uint8_array_to_vec alice_identity_private
  in
  let alice_ephemeral_private_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Signal_protocol_wasm.Rust.Crypto.uint8_array_to_vec alice_ephemeral_private
  in
  let bob_identity_public_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Signal_protocol_wasm.Rust.Crypto.uint8_array_to_vec bob_identity_public
  in
  let bob_signed_prekey_public_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Signal_protocol_wasm.Rust.Crypto.uint8_array_to_vec bob_signed_prekey_public
  in
  let bob_one_time_prekey_opt:Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  =
    Core_models.Option.impl__map #Js_sys.t_Uint8Array
      #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      #(Js_sys.t_Uint8Array -> Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (Core_models.Option.impl__as_ref #Js_sys.t_Uint8Array bob_one_time_prekey_public
        <:
        Core_models.Option.t_Option Js_sys.t_Uint8Array)
      (fun k ->
          let k:Js_sys.t_Uint8Array = k in
          Signal_protocol_wasm.Rust.Crypto.uint8_array_to_vec k
          <:
          Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  in
  match
    x3dh_initiate_internal (Alloc.Vec.impl_1__as_slice alice_identity_private_bytes <: t_Slice u8)
      (Alloc.Vec.impl_1__as_slice alice_ephemeral_private_bytes <: t_Slice u8)
      (Alloc.Vec.impl_1__as_slice bob_identity_public_bytes <: t_Slice u8)
      (Alloc.Vec.impl_1__as_slice bob_signed_prekey_public_bytes <: t_Slice u8)
      (Core_models.Option.impl__map #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          #(t_Slice u8)
          #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global -> t_Slice u8)
          (Core_models.Option.impl__as_ref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
              bob_one_time_prekey_opt
            <:
            Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
          (fun v ->
              let v:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = v in
              Alloc.Vec.impl_1__as_slice #u8 #Alloc.Alloc.t_Global v <: t_Slice u8)
        <:
        Core_models.Option.t_Option (t_Slice u8))
    <:
    Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_X3DHResult
      Signal_protocol_core.Error.t_SignalError
  with
  | Core_models.Result.Result_Ok result ->
    let _:Prims.unit = log "X3DH initiation completed successfully" in
    Core_models.Result.Result_Ok result
    <:
    Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_X3DHResult Wasm_bindgen.t_JsValue
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
    Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_X3DHResult Wasm_bindgen.t_JsValue

assume
val e_': Prims.unit

unfold
let e_ = e_'

/// Initiate X3DH key exchange (Alice\'s side)
///
/// This function performs the X3DH key agreement from the initiator\'s perspective.
/// Alice combines her keys with Bob\'s prekeys to compute a shared secret that
/// both parties can independently derive.
///
/// ## X3DH Protocol Overview
/// The X3DH protocol performs multiple Diffie-Hellman computations:
/// 1. DH1: Alice_Identity_Private × Bob_SignedPrekey_Public
/// 2. DH2: Alice_Ephemeral_Private × Bob_Identity_Public
/// 3. DH3: Alice_Ephemeral_Private × Bob_SignedPrekey_Public
/// 4. DH4: Alice_Ephemeral_Private × Bob_OneTimePrekey_Public (optional)
///
/// The results are concatenated and fed into HKDF to derive the final shared secret.
///
/// ## Security Properties
/// - **Forward Secrecy**: Compromise of long-term keys doesn\'t affect past sessions
/// - **Authentication**: Both parties prove their identity through key ownership
/// - **Asynchronous**: Bob doesn\'t need to be online during key exchange
/// - **Deniability**: No long-term proof of participation in conversations
///
/// ## Parameters
/// - `alice_identity_private`: Alice\'s long-term identity private key (32 bytes)
/// - `alice_ephemeral_private`: Alice\'s session-specific ephemeral private key (32 bytes)
/// - `bob_identity_public`: Bob\'s identity public key (32 bytes)
/// - `bob_signed_prekey_public`: Bob\'s signed prekey public key (32 bytes)
/// - `bob_one_time_prekey_public`: Optional one-time prekey for additional forward secrecy
///
/// ## Returns
/// An `X3DHResult` containing the shared secret and associated data
///
/// ## Example Usage
/// ```rust
/// let result = x3dh_initiate(
///     &alice_identity_private,
///     &alice_ephemeral_private,
///     &bob_identity_public,
///     &bob_signed_prekey_public,
///     Some(bob_one_time_prekey_public)
/// )?;
/// let shared_secret = result.shared_secret();
/// ```
assume
val e___e_ee_wasm_bindgen_generated_x3dh_initiate':
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
    arg3_4_: Prims.unit ->
    arg4_1_: u32 ->
    arg4_2_: Prims.unit ->
    arg4_3_: Prims.unit ->
    arg4_4_: Prims.unit
  -> Wasm_bindgen.Convert.Traits.t_WasmRet (Core_models.Result.t_Result u32 u32)

unfold
let e___e_ee_wasm_bindgen_generated_x3dh_initiate = e___e_ee_wasm_bindgen_generated_x3dh_initiate'

assume
val e___e_ee_wasm_bindgen_generated_x3dh_initiate__e_': Prims.unit

unfold
let e___e_ee_wasm_bindgen_generated_x3dh_initiate__e_ =
  e___e_ee_wasm_bindgen_generated_x3dh_initiate__e_'

/// Respond to X3DH key exchange (Bob\'s side)
///
/// This function performs the X3DH key agreement from the responder\'s perspective.
/// Bob uses his prekeys and Alice\'s ephemeral key to compute the same shared secret
/// that Alice derived on her side.
///
/// ## Protocol Symmetry
/// Bob performs the exact same DH computations as Alice, but uses his private keys
/// instead of Alice\'s. The commutativity property of our simplified ECDH ensures
/// that both parties compute identical shared secrets.
///
/// ## Key Derivation Order
/// Bob must perform the DH computations in the same order as Alice:
/// 1. DH1: Bob_SignedPrekey_Private × Alice_Identity_Public (= Alice\'s DH1)
/// 2. DH2: Bob_Identity_Private × Alice_Ephemeral_Public (= Alice\'s DH2)
/// 3. DH3: Bob_SignedPrekey_Private × Alice_Ephemeral_Public (= Alice\'s DH3)
/// 4. DH4: Bob_OneTimePrekey_Private × Alice_Ephemeral_Public (= Alice\'s DH4, optional)
///
/// ## Parameters
/// - `bob_identity_private`: Bob\'s long-term identity private key (32 bytes)
/// - `bob_signed_prekey_private`: Bob\'s signed prekey private key (32 bytes)
/// - `bob_one_time_prekey_private`: Optional one-time prekey private key (32 bytes)
/// - `alice_identity_public`: Alice\'s identity public key (32 bytes)
/// - `alice_ephemeral_public`: Alice\'s ephemeral public key from the key exchange (32 bytes)
///
/// ## Returns
/// An `X3DHResult` containing the same shared secret Alice computed
///
/// ## Example Usage
/// ```rust
/// let result = x3dh_respond(
///     &bob_identity_private,
///     &bob_signed_prekey_private,
///     Some(bob_one_time_prekey_private),
///     &alice_identity_public,
///     &alice_ephemeral_public
/// )?;
/// let shared_secret = result.shared_secret();
/// ```
let x3dh_respond
      (bob_identity_private bob_signed_prekey_private: Js_sys.t_Uint8Array)
      (bob_one_time_prekey_private: Core_models.Option.t_Option Js_sys.t_Uint8Array)
      (alice_identity_public alice_ephemeral_public: Js_sys.t_Uint8Array)
    : Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_X3DHResult
      Wasm_bindgen.t_JsValue =
  let _:Prims.unit = log "Responding to X3DH key exchange (Bob side)" in
  let bob_identity_private_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Signal_protocol_wasm.Rust.Crypto.uint8_array_to_vec bob_identity_private
  in
  let bob_signed_prekey_private_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Signal_protocol_wasm.Rust.Crypto.uint8_array_to_vec bob_signed_prekey_private
  in
  let alice_identity_public_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Signal_protocol_wasm.Rust.Crypto.uint8_array_to_vec alice_identity_public
  in
  let alice_ephemeral_public_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Signal_protocol_wasm.Rust.Crypto.uint8_array_to_vec alice_ephemeral_public
  in
  let bob_one_time_prekey_opt:Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  =
    Core_models.Option.impl__map #Js_sys.t_Uint8Array
      #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      #(Js_sys.t_Uint8Array -> Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (Core_models.Option.impl__as_ref #Js_sys.t_Uint8Array bob_one_time_prekey_private
        <:
        Core_models.Option.t_Option Js_sys.t_Uint8Array)
      (fun k ->
          let k:Js_sys.t_Uint8Array = k in
          Signal_protocol_wasm.Rust.Crypto.uint8_array_to_vec k
          <:
          Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  in
  match
    x3dh_respond_internal (Alloc.Vec.impl_1__as_slice bob_identity_private_bytes <: t_Slice u8)
      (Alloc.Vec.impl_1__as_slice bob_signed_prekey_private_bytes <: t_Slice u8)
      (Core_models.Option.impl__map #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          #(t_Slice u8)
          #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global -> t_Slice u8)
          (Core_models.Option.impl__as_ref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
              bob_one_time_prekey_opt
            <:
            Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
          (fun v ->
              let v:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = v in
              Alloc.Vec.impl_1__as_slice #u8 #Alloc.Alloc.t_Global v <: t_Slice u8)
        <:
        Core_models.Option.t_Option (t_Slice u8))
      (Alloc.Vec.impl_1__as_slice alice_identity_public_bytes <: t_Slice u8)
      (Alloc.Vec.impl_1__as_slice alice_ephemeral_public_bytes <: t_Slice u8)
    <:
    Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_X3DHResult
      Signal_protocol_core.Error.t_SignalError
  with
  | Core_models.Result.Result_Ok result ->
    let _:Prims.unit = log "X3DH response completed successfully" in
    Core_models.Result.Result_Ok result
    <:
    Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_X3DHResult Wasm_bindgen.t_JsValue
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
    Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_X3DHResult Wasm_bindgen.t_JsValue

assume
val e_ee_1': Prims.unit

unfold
let e_ee_1 = e_ee_1'

/// Respond to X3DH key exchange (Bob\'s side)
///
/// This function performs the X3DH key agreement from the responder\'s perspective.
/// Bob uses his prekeys and Alice\'s ephemeral key to compute the same shared secret
/// that Alice derived on her side.
///
/// ## Protocol Symmetry
/// Bob performs the exact same DH computations as Alice, but uses his private keys
/// instead of Alice\'s. The commutativity property of our simplified ECDH ensures
/// that both parties compute identical shared secrets.
///
/// ## Key Derivation Order
/// Bob must perform the DH computations in the same order as Alice:
/// 1. DH1: Bob_SignedPrekey_Private × Alice_Identity_Public (= Alice\'s DH1)
/// 2. DH2: Bob_Identity_Private × Alice_Ephemeral_Public (= Alice\'s DH2)
/// 3. DH3: Bob_SignedPrekey_Private × Alice_Ephemeral_Public (= Alice\'s DH3)
/// 4. DH4: Bob_OneTimePrekey_Private × Alice_Ephemeral_Public (= Alice\'s DH4, optional)
///
/// ## Parameters
/// - `bob_identity_private`: Bob\'s long-term identity private key (32 bytes)
/// - `bob_signed_prekey_private`: Bob\'s signed prekey private key (32 bytes)
/// - `bob_one_time_prekey_private`: Optional one-time prekey private key (32 bytes)
/// - `alice_identity_public`: Alice\'s identity public key (32 bytes)
/// - `alice_ephemeral_public`: Alice\'s ephemeral public key from the key exchange (32 bytes)
///
/// ## Returns
/// An `X3DHResult` containing the same shared secret Alice computed
///
/// ## Example Usage
/// ```rust
/// let result = x3dh_respond(
///     &bob_identity_private,
///     &bob_signed_prekey_private,
///     Some(bob_one_time_prekey_private),
///     &alice_identity_public,
///     &alice_ephemeral_public
/// )?;
/// let shared_secret = result.shared_secret();
/// ```
assume
val e_ee_1__e_ee_wasm_bindgen_generated_x3dh_respond':
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
    arg3_4_: Prims.unit ->
    arg4_1_: u32 ->
    arg4_2_: Prims.unit ->
    arg4_3_: Prims.unit ->
    arg4_4_: Prims.unit
  -> Wasm_bindgen.Convert.Traits.t_WasmRet (Core_models.Result.t_Result u32 u32)

unfold
let e_ee_1__e_ee_wasm_bindgen_generated_x3dh_respond =
  e_ee_1__e_ee_wasm_bindgen_generated_x3dh_respond'

assume
val e_ee_1__e_ee_wasm_bindgen_generated_x3dh_respond__e_': Prims.unit

unfold
let e_ee_1__e_ee_wasm_bindgen_generated_x3dh_respond__e_ =
  e_ee_1__e_ee_wasm_bindgen_generated_x3dh_respond__e_'
