module Signal_protocol_wasm.Rust.Types
#set-options "--fuel 0 --ifuel 1 --z3rlimit 40"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Js_sys in
  let open Wasm_bindgen.Convert.Traits in
  let open Wasm_bindgen.Describe in
  ()

/// Cryptographic key pair structure
///
/// Represents a public/private key pair used in the Signal Protocol.
/// The keys are stored as byte vectors internally but exposed to JavaScript
/// as Uint8Array objects for compatibility.
///
/// ## Security Note
/// Private keys should be handled with extreme care and never exposed
/// in logs or transmitted over insecure channels.
type t_KeyPair = {
  f_public_key:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global;
  f_private_key:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global
}

let impl_17: Core_models.Clone.t_Clone t_KeyPair =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_18': Core_models.Fmt.t_Debug t_KeyPair

unfold
let impl_18 = impl_18'

let e_: Prims.unit = ()

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val e___impl': Serde_core.Ser.t_Serialize t_KeyPair

unfold
let e___impl = e___impl'

let e_ee_1: Prims.unit = ()

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val e_ee_1__impl': Serde_core.De.t_Deserialize t_KeyPair

unfold
let e_ee_1__impl = e_ee_1__impl'

assume
val e_ee_1__f_deserialize__impl__t_e_ee_Field': eqtype

unfold
let e_ee_1__f_deserialize__impl__t_e_ee_Field = e_ee_1__f_deserialize__impl__t_e_ee_Field'

assume
val e_ee_1__f_deserialize__impl__t_e_ee_FieldVisitor': eqtype

unfold
let e_ee_1__f_deserialize__impl__t_e_ee_FieldVisitor =
  e_ee_1__f_deserialize__impl__t_e_ee_FieldVisitor'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val e_ee_1__f_deserialize__impl__impl': Serde_core.De.t_Visitor
e_ee_1__f_deserialize__impl__t_e_ee_FieldVisitor

unfold
let e_ee_1__f_deserialize__impl__impl = e_ee_1__f_deserialize__impl__impl'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val e_ee_1__f_deserialize__impl__impl_1': Serde_core.De.t_Deserialize
e_ee_1__f_deserialize__impl__t_e_ee_Field

unfold
let e_ee_1__f_deserialize__impl__impl_1 = e_ee_1__f_deserialize__impl__impl_1'

assume
val e_ee_1__f_deserialize__impl__t_e_ee_Visitor': eqtype

unfold
let e_ee_1__f_deserialize__impl__t_e_ee_Visitor = e_ee_1__f_deserialize__impl__t_e_ee_Visitor'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val e_ee_1__f_deserialize__impl__impl_2': Serde_core.De.t_Visitor
e_ee_1__f_deserialize__impl__t_e_ee_Visitor

unfold
let e_ee_1__f_deserialize__impl__impl_2 = e_ee_1__f_deserialize__impl__impl_2'

assume
val e_ee_1__f_deserialize__impl__v_FIELDS': t_Slice string

unfold
let e_ee_1__f_deserialize__impl__v_FIELDS = e_ee_1__f_deserialize__impl__v_FIELDS'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl': Wasm_bindgen.__rt.Marker.t_SupportsConstructor t_KeyPair

unfold
let impl = impl'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_1': Wasm_bindgen.__rt.Marker.t_SupportsInstanceProperty t_KeyPair

unfold
let impl_1 = impl_1'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_2': Wasm_bindgen.__rt.Marker.t_SupportsStaticProperty t_KeyPair

unfold
let impl_2 = impl_2'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_3': Wasm_bindgen.Describe.t_WasmDescribe t_KeyPair

unfold
let impl_3 = impl_3'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_4': Wasm_bindgen.Convert.Traits.t_IntoWasmAbi t_KeyPair

unfold
let impl_4 = impl_4'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_5': Wasm_bindgen.Convert.Traits.t_FromWasmAbi t_KeyPair

unfold
let impl_5 = impl_5'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_6': Core_models.Convert.t_From Wasm_bindgen.t_JsValue t_KeyPair

unfold
let impl_6 = impl_6'

assume
val f_from__impl_6__e_ee_wbg_keypair_new': u32 -> u32

unfold
let f_from__impl_6__e_ee_wbg_keypair_new = f_from__impl_6__e_ee_wbg_keypair_new'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_7': Wasm_bindgen.Convert.Traits.t_RefFromWasmAbi t_KeyPair

unfold
let impl_7 = impl_7'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_8': Wasm_bindgen.Convert.Traits.t_RefMutFromWasmAbi t_KeyPair

unfold
let impl_8 = impl_8'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_9': Wasm_bindgen.Convert.Traits.t_LongRefFromWasmAbi t_KeyPair

unfold
let impl_9 = impl_9'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_10': Wasm_bindgen.Convert.Traits.t_OptionIntoWasmAbi t_KeyPair

unfold
let impl_10 = impl_10'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_11': Wasm_bindgen.Convert.Traits.t_OptionFromWasmAbi t_KeyPair

unfold
let impl_11 = impl_11'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_12': Wasm_bindgen.Convert.Traits.t_TryFromJsValue t_KeyPair

unfold
let impl_12 = impl_12'

assume
val f_try_from_js_value__impl_12__e_ee_wbg_keypair_unwrap': u32 -> u32

unfold
let f_try_from_js_value__impl_12__e_ee_wbg_keypair_unwrap =
  f_try_from_js_value__impl_12__e_ee_wbg_keypair_unwrap'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_13': Wasm_bindgen.Describe.t_WasmDescribeVector t_KeyPair

unfold
let impl_13 = impl_13'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_14': Wasm_bindgen.Convert.Traits.t_VectorIntoWasmAbi t_KeyPair

unfold
let impl_14 = impl_14'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_15': Wasm_bindgen.Convert.Traits.t_VectorFromWasmAbi t_KeyPair

unfold
let impl_15 = impl_15'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_16': Wasm_bindgen.__rt.t_VectorIntoJsValue t_KeyPair

unfold
let impl_16 = impl_16'

/// Get the public key as a JavaScript Uint8Array
///
/// The public key can be safely shared with other parties for
/// encryption, signature verification, or key agreement protocols.
let impl_KeyPair__public_key (self: t_KeyPair) : Js_sys.t_Uint8Array =
  Core_models.Convert.f_from #Js_sys.t_Uint8Array
    #(t_Slice u8)
    #FStar.Tactics.Typeclasses.solve
    (self.f_public_key.[ Core_models.Ops.Range.RangeFull <: Core_models.Ops.Range.t_RangeFull ]
      <:
      t_Slice u8)

/// Get the private key as a JavaScript Uint8Array
///
/// ⚠\u{fe0f} **WARNING**: Private keys must be handled securely.
/// Only access this when absolutely necessary for cryptographic operations.
let impl_KeyPair__private_key (self: t_KeyPair) : Js_sys.t_Uint8Array =
  Core_models.Convert.f_from #Js_sys.t_Uint8Array
    #(t_Slice u8)
    #FStar.Tactics.Typeclasses.solve
    (self.f_private_key.[ Core_models.Ops.Range.RangeFull <: Core_models.Ops.Range.t_RangeFull ]
      <:
      t_Slice u8)

assume
val impl_KeyPair__public_key__e_': Prims.unit

unfold
let impl_KeyPair__public_key__e_ = impl_KeyPair__public_key__e_'

/// Get the public key as a JavaScript Uint8Array
///
/// The public key can be safely shared with other parties for
/// encryption, signature verification, or key agreement protocols.
assume
val impl_KeyPair__public_key__e___e_ee_wasm_bindgen_generated_KeyPair_public_key': me: u32
  -> Wasm_bindgen.Convert.Traits.t_WasmRet u32

unfold
let impl_KeyPair__public_key__e___e_ee_wasm_bindgen_generated_KeyPair_public_key =
  impl_KeyPair__public_key__e___e_ee_wasm_bindgen_generated_KeyPair_public_key'

assume
val impl_KeyPair__public_key__e___e_ee_wasm_bindgen_generated_KeyPair_public_key__e_': Prims.unit

unfold
let impl_KeyPair__public_key__e___e_ee_wasm_bindgen_generated_KeyPair_public_key__e_ =
  impl_KeyPair__public_key__e___e_ee_wasm_bindgen_generated_KeyPair_public_key__e_'

assume
val impl_KeyPair__private_key__e_': Prims.unit

unfold
let impl_KeyPair__private_key__e_ = impl_KeyPair__private_key__e_'

/// Get the private key as a JavaScript Uint8Array
///
/// ⚠\u{fe0f} **WARNING**: Private keys must be handled securely.
/// Only access this when absolutely necessary for cryptographic operations.
assume
val impl_KeyPair__private_key__e___e_ee_wasm_bindgen_generated_KeyPair_private_key': me: u32
  -> Wasm_bindgen.Convert.Traits.t_WasmRet u32

unfold
let impl_KeyPair__private_key__e___e_ee_wasm_bindgen_generated_KeyPair_private_key =
  impl_KeyPair__private_key__e___e_ee_wasm_bindgen_generated_KeyPair_private_key'

assume
val impl_KeyPair__private_key__e___e_ee_wasm_bindgen_generated_KeyPair_private_key__e_': Prims.unit

unfold
let impl_KeyPair__private_key__e___e_ee_wasm_bindgen_generated_KeyPair_private_key__e_ =
  impl_KeyPair__private_key__e___e_ee_wasm_bindgen_generated_KeyPair_private_key__e_'

/// Result of X3DH key exchange protocol
///
/// Contains the shared secret and associated data produced by the X3DH
/// key agreement protocol. This data is used to initialize secure
/// communication channels between two parties.
///
/// ## X3DH Protocol
/// The Extended Triple Diffie-Hellman (X3DH) is Signal\'s key agreement
/// protocol that provides mutual authentication and forward secrecy.
type t_X3DHResult = {
  f_shared_secret:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global;
  f_associated_data:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global
}

let impl_37: Core_models.Clone.t_Clone t_X3DHResult =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_38': Core_models.Fmt.t_Debug t_X3DHResult

unfold
let impl_38 = impl_38'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_20': Wasm_bindgen.__rt.Marker.t_SupportsConstructor t_X3DHResult

unfold
let impl_20 = impl_20'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_21': Wasm_bindgen.__rt.Marker.t_SupportsInstanceProperty t_X3DHResult

unfold
let impl_21 = impl_21'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_22': Wasm_bindgen.__rt.Marker.t_SupportsStaticProperty t_X3DHResult

unfold
let impl_22 = impl_22'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_23': Wasm_bindgen.Describe.t_WasmDescribe t_X3DHResult

unfold
let impl_23 = impl_23'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_24': Wasm_bindgen.Convert.Traits.t_IntoWasmAbi t_X3DHResult

unfold
let impl_24 = impl_24'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_25': Wasm_bindgen.Convert.Traits.t_FromWasmAbi t_X3DHResult

unfold
let impl_25 = impl_25'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_26': Core_models.Convert.t_From Wasm_bindgen.t_JsValue t_X3DHResult

unfold
let impl_26 = impl_26'

assume
val f_from__impl_26__e_ee_wbg_x3dhresult_new': u32 -> u32

unfold
let f_from__impl_26__e_ee_wbg_x3dhresult_new = f_from__impl_26__e_ee_wbg_x3dhresult_new'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_27': Wasm_bindgen.Convert.Traits.t_RefFromWasmAbi t_X3DHResult

unfold
let impl_27 = impl_27'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_28': Wasm_bindgen.Convert.Traits.t_RefMutFromWasmAbi t_X3DHResult

unfold
let impl_28 = impl_28'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_29': Wasm_bindgen.Convert.Traits.t_LongRefFromWasmAbi t_X3DHResult

unfold
let impl_29 = impl_29'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_30': Wasm_bindgen.Convert.Traits.t_OptionIntoWasmAbi t_X3DHResult

unfold
let impl_30 = impl_30'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_31': Wasm_bindgen.Convert.Traits.t_OptionFromWasmAbi t_X3DHResult

unfold
let impl_31 = impl_31'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_32': Wasm_bindgen.Convert.Traits.t_TryFromJsValue t_X3DHResult

unfold
let impl_32 = impl_32'

assume
val f_try_from_js_value__impl_32__e_ee_wbg_x3dhresult_unwrap': u32 -> u32

unfold
let f_try_from_js_value__impl_32__e_ee_wbg_x3dhresult_unwrap =
  f_try_from_js_value__impl_32__e_ee_wbg_x3dhresult_unwrap'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_33': Wasm_bindgen.Describe.t_WasmDescribeVector t_X3DHResult

unfold
let impl_33 = impl_33'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_34': Wasm_bindgen.Convert.Traits.t_VectorIntoWasmAbi t_X3DHResult

unfold
let impl_34 = impl_34'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_35': Wasm_bindgen.Convert.Traits.t_VectorFromWasmAbi t_X3DHResult

unfold
let impl_35 = impl_35'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_36': Wasm_bindgen.__rt.t_VectorIntoJsValue t_X3DHResult

unfold
let impl_36 = impl_36'

/// Get the shared secret as a JavaScript Uint8Array
///
/// This secret should be used immediately for key derivation and
/// then securely wiped from memory when no longer needed.
let impl_X3DHResult__shared_secret (self: t_X3DHResult) : Js_sys.t_Uint8Array =
  Core_models.Convert.f_from #Js_sys.t_Uint8Array
    #(t_Slice u8)
    #FStar.Tactics.Typeclasses.solve
    (self.f_shared_secret.[ Core_models.Ops.Range.RangeFull <: Core_models.Ops.Range.t_RangeFull ]
      <:
      t_Slice u8)

/// Get the associated data as a JavaScript Uint8Array
///
/// Associated data provides additional context for the key exchange
/// and can be used for protocol versioning or authentication.
let impl_X3DHResult__associated_data (self: t_X3DHResult) : Js_sys.t_Uint8Array =
  Core_models.Convert.f_from #Js_sys.t_Uint8Array
    #(t_Slice u8)
    #FStar.Tactics.Typeclasses.solve
    (self.f_associated_data.[ Core_models.Ops.Range.RangeFull <: Core_models.Ops.Range.t_RangeFull ]
      <:
      t_Slice u8)

assume
val impl_X3DHResult__shared_secret__e_': Prims.unit

unfold
let impl_X3DHResult__shared_secret__e_ = impl_X3DHResult__shared_secret__e_'

/// Get the shared secret as a JavaScript Uint8Array
///
/// This secret should be used immediately for key derivation and
/// then securely wiped from memory when no longer needed.
assume
val impl_X3DHResult__shared_secret__e___e_ee_wasm_bindgen_generated_X3DHResult_shared_secret':
    me: u32
  -> Wasm_bindgen.Convert.Traits.t_WasmRet u32

unfold
let impl_X3DHResult__shared_secret__e___e_ee_wasm_bindgen_generated_X3DHResult_shared_secret =
  impl_X3DHResult__shared_secret__e___e_ee_wasm_bindgen_generated_X3DHResult_shared_secret'

assume
val impl_X3DHResult__shared_secret__e___e_ee_wasm_bindgen_generated_X3DHResult_shared_secret__e_': Prims.unit

unfold
let impl_X3DHResult__shared_secret__e___e_ee_wasm_bindgen_generated_X3DHResult_shared_secret__e_ =
  impl_X3DHResult__shared_secret__e___e_ee_wasm_bindgen_generated_X3DHResult_shared_secret__e_'

assume
val impl_X3DHResult__associated_data__e_': Prims.unit

unfold
let impl_X3DHResult__associated_data__e_ = impl_X3DHResult__associated_data__e_'

/// Get the associated data as a JavaScript Uint8Array
///
/// Associated data provides additional context for the key exchange
/// and can be used for protocol versioning or authentication.
assume
val impl_X3DHResult__associated_data__e___e_ee_wasm_bindgen_generated_X3DHResult_associated_data':
    me: u32
  -> Wasm_bindgen.Convert.Traits.t_WasmRet u32

unfold
let impl_X3DHResult__associated_data__e___e_ee_wasm_bindgen_generated_X3DHResult_associated_data =
  impl_X3DHResult__associated_data__e___e_ee_wasm_bindgen_generated_X3DHResult_associated_data'

assume
val impl_X3DHResult__associated_data__e___e_ee_wasm_bindgen_generated_X3DHResult_associated_data__e_': Prims.unit

unfold
let impl_X3DHResult__associated_data__e___e_ee_wasm_bindgen_generated_X3DHResult_associated_data__e_ =
  impl_X3DHResult__associated_data__e___e_ee_wasm_bindgen_generated_X3DHResult_associated_data__e_'

/// Result of message encryption operation
///
/// Contains both the encrypted ciphertext and the derived message key.
/// The message key can be stored for future decryption operations,
/// enabling asynchronous message processing.
///
/// ## Forward Secrecy
/// Each message uses a unique derived key, ensuring that compromise
/// of one message key doesn\'t affect the security of other messages.
type t_EncryptionResult = {
  f_ciphertext:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global;
  f_message_key:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global
}

let impl_57: Core_models.Clone.t_Clone t_EncryptionResult =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_58': Core_models.Fmt.t_Debug t_EncryptionResult

unfold
let impl_58 = impl_58'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_40': Wasm_bindgen.__rt.Marker.t_SupportsConstructor t_EncryptionResult

unfold
let impl_40 = impl_40'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_41': Wasm_bindgen.__rt.Marker.t_SupportsInstanceProperty t_EncryptionResult

unfold
let impl_41 = impl_41'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_42': Wasm_bindgen.__rt.Marker.t_SupportsStaticProperty t_EncryptionResult

unfold
let impl_42 = impl_42'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_43': Wasm_bindgen.Describe.t_WasmDescribe t_EncryptionResult

unfold
let impl_43 = impl_43'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_44': Wasm_bindgen.Convert.Traits.t_IntoWasmAbi t_EncryptionResult

unfold
let impl_44 = impl_44'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_45': Wasm_bindgen.Convert.Traits.t_FromWasmAbi t_EncryptionResult

unfold
let impl_45 = impl_45'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_46': Core_models.Convert.t_From Wasm_bindgen.t_JsValue t_EncryptionResult

unfold
let impl_46 = impl_46'

assume
val f_from__impl_46__e_ee_wbg_encryptionresult_new': u32 -> u32

unfold
let f_from__impl_46__e_ee_wbg_encryptionresult_new = f_from__impl_46__e_ee_wbg_encryptionresult_new'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_47': Wasm_bindgen.Convert.Traits.t_RefFromWasmAbi t_EncryptionResult

unfold
let impl_47 = impl_47'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_48': Wasm_bindgen.Convert.Traits.t_RefMutFromWasmAbi t_EncryptionResult

unfold
let impl_48 = impl_48'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_49': Wasm_bindgen.Convert.Traits.t_LongRefFromWasmAbi t_EncryptionResult

unfold
let impl_49 = impl_49'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_50': Wasm_bindgen.Convert.Traits.t_OptionIntoWasmAbi t_EncryptionResult

unfold
let impl_50 = impl_50'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_51': Wasm_bindgen.Convert.Traits.t_OptionFromWasmAbi t_EncryptionResult

unfold
let impl_51 = impl_51'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_52': Wasm_bindgen.Convert.Traits.t_TryFromJsValue t_EncryptionResult

unfold
let impl_52 = impl_52'

assume
val f_try_from_js_value__impl_52__e_ee_wbg_encryptionresult_unwrap': u32 -> u32

unfold
let f_try_from_js_value__impl_52__e_ee_wbg_encryptionresult_unwrap =
  f_try_from_js_value__impl_52__e_ee_wbg_encryptionresult_unwrap'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_53': Wasm_bindgen.Describe.t_WasmDescribeVector t_EncryptionResult

unfold
let impl_53 = impl_53'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_54': Wasm_bindgen.Convert.Traits.t_VectorIntoWasmAbi t_EncryptionResult

unfold
let impl_54 = impl_54'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_55': Wasm_bindgen.Convert.Traits.t_VectorFromWasmAbi t_EncryptionResult

unfold
let impl_55 = impl_55'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_56': Wasm_bindgen.__rt.t_VectorIntoJsValue t_EncryptionResult

unfold
let impl_56 = impl_56'

/// Get the ciphertext as a JavaScript Uint8Array
///
/// The ciphertext includes the nonce and authentication tag,
/// making it self-contained for transmission and storage.
let impl_EncryptionResult__ciphertext (self: t_EncryptionResult) : Js_sys.t_Uint8Array =
  Core_models.Convert.f_from #Js_sys.t_Uint8Array
    #(t_Slice u8)
    #FStar.Tactics.Typeclasses.solve
    (self.f_ciphertext.[ Core_models.Ops.Range.RangeFull <: Core_models.Ops.Range.t_RangeFull ]
      <:
      t_Slice u8)

/// Get the message key as a JavaScript Uint8Array
///
/// This key is required for decryption and should be stored
/// securely alongside the ciphertext if needed for later access.
let impl_EncryptionResult__message_key (self: t_EncryptionResult) : Js_sys.t_Uint8Array =
  Core_models.Convert.f_from #Js_sys.t_Uint8Array
    #(t_Slice u8)
    #FStar.Tactics.Typeclasses.solve
    (self.f_message_key.[ Core_models.Ops.Range.RangeFull <: Core_models.Ops.Range.t_RangeFull ]
      <:
      t_Slice u8)

assume
val impl_EncryptionResult__ciphertext__e_': Prims.unit

unfold
let impl_EncryptionResult__ciphertext__e_ = impl_EncryptionResult__ciphertext__e_'

/// Get the ciphertext as a JavaScript Uint8Array
///
/// The ciphertext includes the nonce and authentication tag,
/// making it self-contained for transmission and storage.
assume
val impl_EncryptionResult__ciphertext__e___e_ee_wasm_bindgen_generated_EncryptionResult_ciphertext':
    me: u32
  -> Wasm_bindgen.Convert.Traits.t_WasmRet u32

unfold
let impl_EncryptionResult__ciphertext__e___e_ee_wasm_bindgen_generated_EncryptionResult_ciphertext =
  impl_EncryptionResult__ciphertext__e___e_ee_wasm_bindgen_generated_EncryptionResult_ciphertext'

assume
val impl_EncryptionResult__ciphertext__e___e_ee_wasm_bindgen_generated_EncryptionResult_ciphertext__e_': Prims.unit

unfold
let
impl_EncryptionResult__ciphertext__e___e_ee_wasm_bindgen_generated_EncryptionResult_ciphertext__e_ =
  impl_EncryptionResult__ciphertext__e___e_ee_wasm_bindgen_generated_EncryptionResult_ciphertext__e_'

assume
val impl_EncryptionResult__message_key__e_': Prims.unit

unfold
let impl_EncryptionResult__message_key__e_ = impl_EncryptionResult__message_key__e_'

/// Get the message key as a JavaScript Uint8Array
///
/// This key is required for decryption and should be stored
/// securely alongside the ciphertext if needed for later access.
assume
val impl_EncryptionResult__message_key__e___e_ee_wasm_bindgen_generated_EncryptionResult_message_key':
    me: u32
  -> Wasm_bindgen.Convert.Traits.t_WasmRet u32

unfold
let impl_EncryptionResult__message_key__e___e_ee_wasm_bindgen_generated_EncryptionResult_message_key =
  impl_EncryptionResult__message_key__e___e_ee_wasm_bindgen_generated_EncryptionResult_message_key'

assume
val impl_EncryptionResult__message_key__e___e_ee_wasm_bindgen_generated_EncryptionResult_message_key__e_': Prims.unit

unfold
let
impl_EncryptionResult__message_key__e___e_ee_wasm_bindgen_generated_EncryptionResult_message_key__e_ =
  impl_EncryptionResult__message_key__e___e_ee_wasm_bindgen_generated_EncryptionResult_message_key__e_'
