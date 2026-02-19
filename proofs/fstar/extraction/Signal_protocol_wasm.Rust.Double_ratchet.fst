module Signal_protocol_wasm.Rust.Double_ratchet
#set-options "--fuel 0 --ifuel 1 --z3rlimit 40"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Js_sys in
  let open Signal_protocol_core.Error in
  let open Wasm_bindgen.Convert.Traits in
  let open Wasm_bindgen.Describe in
  ()

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

let core_to_wasm_keypair (k: Signal_protocol_core.Types.t_KeyPair)
    : Signal_protocol_wasm.Rust.Types.t_KeyPair =
  {
    Signal_protocol_wasm.Rust.Types.f_public_key = k.Signal_protocol_core.Types.f_public_key;
    Signal_protocol_wasm.Rust.Types.f_private_key = k.Signal_protocol_core.Types.f_private_key
  }
  <:
  Signal_protocol_wasm.Rust.Types.t_KeyPair

let wasm_to_core_keypair (k: Signal_protocol_wasm.Rust.Types.t_KeyPair)
    : Signal_protocol_core.Types.t_KeyPair =
  {
    Signal_protocol_core.Types.f_public_key
    =
    Core_models.Clone.f_clone #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      #FStar.Tactics.Typeclasses.solve
      k.Signal_protocol_wasm.Rust.Types.f_public_key;
    Signal_protocol_core.Types.f_private_key
    =
    Core_models.Clone.f_clone #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      #FStar.Tactics.Typeclasses.solve
      k.Signal_protocol_wasm.Rust.Types.f_private_key
  }
  <:
  Signal_protocol_core.Types.t_KeyPair

type t_DoubleRatchetState = {
  f_root_key:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global;
  f_sending_chain_key:Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global);
  f_receiving_chain_key:Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global);
  f_sending_dh_keypair:Core_models.Option.t_Option Signal_protocol_wasm.Rust.Types.t_KeyPair;
  f_receiving_dh_public_key:Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global);
  f_sending_message_number:u32;
  f_receiving_message_number:u32;
  f_previous_chain_length:u32;
  f_skipped_message_keys:Alloc.Collections.Btree.Map.t_BTreeMap Alloc.String.t_String
    (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
    Alloc.Alloc.t_Global
}

let core_to_wasm_state (core: Signal_protocol_core.Double_ratchet.t_DoubleRatchetState)
    : t_DoubleRatchetState =
  {
    f_root_key = core.Signal_protocol_core.Double_ratchet.f_root_key;
    f_sending_chain_key = core.Signal_protocol_core.Double_ratchet.f_sending_chain_key;
    f_receiving_chain_key = core.Signal_protocol_core.Double_ratchet.f_receiving_chain_key;
    f_sending_dh_keypair
    =
    Core_models.Option.impl__map #Signal_protocol_core.Types.t_KeyPair
      #Signal_protocol_wasm.Rust.Types.t_KeyPair
      #(Signal_protocol_core.Types.t_KeyPair -> Signal_protocol_wasm.Rust.Types.t_KeyPair)
      core.Signal_protocol_core.Double_ratchet.f_sending_dh_keypair
      core_to_wasm_keypair;
    f_receiving_dh_public_key = core.Signal_protocol_core.Double_ratchet.f_receiving_dh_public_key;
    f_sending_message_number = core.Signal_protocol_core.Double_ratchet.f_sending_message_number;
    f_receiving_message_number = core.Signal_protocol_core.Double_ratchet.f_receiving_message_number;
    f_previous_chain_length = core.Signal_protocol_core.Double_ratchet.f_previous_chain_length;
    f_skipped_message_keys = core.Signal_protocol_core.Double_ratchet.f_skipped_message_keys
  }
  <:
  t_DoubleRatchetState

let wasm_to_core_state (wasm: t_DoubleRatchetState)
    : Signal_protocol_core.Double_ratchet.t_DoubleRatchetState =
  {
    Signal_protocol_core.Double_ratchet.f_root_key
    =
    Core_models.Clone.f_clone #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      #FStar.Tactics.Typeclasses.solve
      wasm.f_root_key;
    Signal_protocol_core.Double_ratchet.f_sending_chain_key
    =
    Core_models.Clone.f_clone #(Core_models.Option.t_Option
        (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
      #FStar.Tactics.Typeclasses.solve
      wasm.f_sending_chain_key;
    Signal_protocol_core.Double_ratchet.f_receiving_chain_key
    =
    Core_models.Clone.f_clone #(Core_models.Option.t_Option
        (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
      #FStar.Tactics.Typeclasses.solve
      wasm.f_receiving_chain_key;
    Signal_protocol_core.Double_ratchet.f_sending_dh_keypair
    =
    Core_models.Option.impl__map #Signal_protocol_wasm.Rust.Types.t_KeyPair
      #Signal_protocol_core.Types.t_KeyPair
      #(Signal_protocol_wasm.Rust.Types.t_KeyPair -> Signal_protocol_core.Types.t_KeyPair)
      (Core_models.Option.impl__as_ref #Signal_protocol_wasm.Rust.Types.t_KeyPair
          wasm.f_sending_dh_keypair
        <:
        Core_models.Option.t_Option Signal_protocol_wasm.Rust.Types.t_KeyPair)
      wasm_to_core_keypair;
    Signal_protocol_core.Double_ratchet.f_receiving_dh_public_key
    =
    Core_models.Clone.f_clone #(Core_models.Option.t_Option
        (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
      #FStar.Tactics.Typeclasses.solve
      wasm.f_receiving_dh_public_key;
    Signal_protocol_core.Double_ratchet.f_sending_message_number = wasm.f_sending_message_number;
    Signal_protocol_core.Double_ratchet.f_receiving_message_number = wasm.f_receiving_message_number;
    Signal_protocol_core.Double_ratchet.f_previous_chain_length = wasm.f_previous_chain_length;
    Signal_protocol_core.Double_ratchet.f_skipped_message_keys
    =
    Core_models.Clone.f_clone #(Alloc.Collections.Btree.Map.t_BTreeMap Alloc.String.t_String
          (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          Alloc.Alloc.t_Global)
      #FStar.Tactics.Typeclasses.solve
      wasm.f_skipped_message_keys
  }
  <:
  Signal_protocol_core.Double_ratchet.t_DoubleRatchetState

let impl_17: Core_models.Clone.t_Clone t_DoubleRatchetState =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl': Wasm_bindgen.__rt.Marker.t_SupportsConstructor t_DoubleRatchetState

unfold
let impl = impl'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_1': Wasm_bindgen.__rt.Marker.t_SupportsInstanceProperty t_DoubleRatchetState

unfold
let impl_1 = impl_1'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_2': Wasm_bindgen.__rt.Marker.t_SupportsStaticProperty t_DoubleRatchetState

unfold
let impl_2 = impl_2'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_3': Wasm_bindgen.Describe.t_WasmDescribe t_DoubleRatchetState

unfold
let impl_3 = impl_3'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_4': Wasm_bindgen.Convert.Traits.t_IntoWasmAbi t_DoubleRatchetState

unfold
let impl_4 = impl_4'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_5': Wasm_bindgen.Convert.Traits.t_FromWasmAbi t_DoubleRatchetState

unfold
let impl_5 = impl_5'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_6': Core_models.Convert.t_From Wasm_bindgen.t_JsValue t_DoubleRatchetState

unfold
let impl_6 = impl_6'

assume
val f_from__impl_6__e_ee_wbg_doubleratchetstate_new': u32 -> u32

unfold
let f_from__impl_6__e_ee_wbg_doubleratchetstate_new =
  f_from__impl_6__e_ee_wbg_doubleratchetstate_new'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_7': Wasm_bindgen.Convert.Traits.t_RefFromWasmAbi t_DoubleRatchetState

unfold
let impl_7 = impl_7'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_8': Wasm_bindgen.Convert.Traits.t_RefMutFromWasmAbi t_DoubleRatchetState

unfold
let impl_8 = impl_8'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_9': Wasm_bindgen.Convert.Traits.t_LongRefFromWasmAbi t_DoubleRatchetState

unfold
let impl_9 = impl_9'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_10': Wasm_bindgen.Convert.Traits.t_OptionIntoWasmAbi t_DoubleRatchetState

unfold
let impl_10 = impl_10'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_11': Wasm_bindgen.Convert.Traits.t_OptionFromWasmAbi t_DoubleRatchetState

unfold
let impl_11 = impl_11'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_12': Wasm_bindgen.Convert.Traits.t_TryFromJsValue t_DoubleRatchetState

unfold
let impl_12 = impl_12'

assume
val f_try_from_js_value__impl_12__e_ee_wbg_doubleratchetstate_unwrap': u32 -> u32

unfold
let f_try_from_js_value__impl_12__e_ee_wbg_doubleratchetstate_unwrap =
  f_try_from_js_value__impl_12__e_ee_wbg_doubleratchetstate_unwrap'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_13': Wasm_bindgen.Describe.t_WasmDescribeVector t_DoubleRatchetState

unfold
let impl_13 = impl_13'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_14': Wasm_bindgen.Convert.Traits.t_VectorIntoWasmAbi t_DoubleRatchetState

unfold
let impl_14 = impl_14'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_15': Wasm_bindgen.Convert.Traits.t_VectorFromWasmAbi t_DoubleRatchetState

unfold
let impl_15 = impl_15'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_16': Wasm_bindgen.__rt.t_VectorIntoJsValue t_DoubleRatchetState

unfold
let impl_16 = impl_16'

let impl_DoubleRatchetState__new (_: Prims.unit) : t_DoubleRatchetState =
  core_to_wasm_state (Signal_protocol_core.Double_ratchet.impl_DoubleRatchetState__new ()
      <:
      Signal_protocol_core.Double_ratchet.t_DoubleRatchetState)

let impl_DoubleRatchetState__root_key (self: t_DoubleRatchetState) : Js_sys.t_Uint8Array =
  Core_models.Convert.f_from #Js_sys.t_Uint8Array
    #(t_Slice u8)
    #FStar.Tactics.Typeclasses.solve
    (self.f_root_key.[ Core_models.Ops.Range.RangeFull <: Core_models.Ops.Range.t_RangeFull ]
      <:
      t_Slice u8)

let impl_DoubleRatchetState__sending_message_number (self: t_DoubleRatchetState) : u32 =
  self.f_sending_message_number

let impl_DoubleRatchetState__receiving_message_number (self: t_DoubleRatchetState) : u32 =
  self.f_receiving_message_number

let impl_DoubleRatchetState__skipped_keys_count (self: t_DoubleRatchetState) : usize =
  Alloc.Collections.Btree.Map.impl_92__len #Alloc.String.t_String
    #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
    #Alloc.Alloc.t_Global
    self.f_skipped_message_keys

assume
val impl_DoubleRatchetState__new__e_': Prims.unit

unfold
let impl_DoubleRatchetState__new__e_ = impl_DoubleRatchetState__new__e_'

assume
val impl_DoubleRatchetState__new__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_new':
    Prims.unit
  -> Wasm_bindgen.Convert.Traits.t_WasmRet u32

unfold
let impl_DoubleRatchetState__new__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_new =
  impl_DoubleRatchetState__new__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_new'

assume
val impl_DoubleRatchetState__new__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_new__e_': Prims.unit

unfold
let impl_DoubleRatchetState__new__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_new__e_ =
  impl_DoubleRatchetState__new__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_new__e_'

assume
val impl_DoubleRatchetState__root_key__e_': Prims.unit

unfold
let impl_DoubleRatchetState__root_key__e_ = impl_DoubleRatchetState__root_key__e_'

assume
val impl_DoubleRatchetState__root_key__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_root_key':
    me: u32
  -> Wasm_bindgen.Convert.Traits.t_WasmRet u32

unfold
let impl_DoubleRatchetState__root_key__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_root_key =
  impl_DoubleRatchetState__root_key__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_root_key'

assume
val impl_DoubleRatchetState__root_key__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_root_key__e_': Prims.unit

unfold
let
impl_DoubleRatchetState__root_key__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_root_key__e_ =
  impl_DoubleRatchetState__root_key__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_root_key__e_'

assume
val impl_DoubleRatchetState__sending_message_number__e_': Prims.unit

unfold
let impl_DoubleRatchetState__sending_message_number__e_ =
  impl_DoubleRatchetState__sending_message_number__e_'

assume
val impl_DoubleRatchetState__sending_message_number__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_sending_message_number':
    me: u32
  -> Wasm_bindgen.Convert.Traits.t_WasmRet u32

unfold
let
impl_DoubleRatchetState__sending_message_number__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_sending_message_number =
  impl_DoubleRatchetState__sending_message_number__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_sending_message_number'

assume
val impl_DoubleRatchetState__sending_message_number__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_sending_message_number__e_': Prims.unit

unfold
let
impl_DoubleRatchetState__sending_message_number__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_sending_message_number__e_ =
  impl_DoubleRatchetState__sending_message_number__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_sending_message_number__e_'

assume
val impl_DoubleRatchetState__receiving_message_number__e_': Prims.unit

unfold
let impl_DoubleRatchetState__receiving_message_number__e_ =
  impl_DoubleRatchetState__receiving_message_number__e_'

assume
val impl_DoubleRatchetState__receiving_message_number__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_receiving_message_number':
    me: u32
  -> Wasm_bindgen.Convert.Traits.t_WasmRet u32

unfold
let
impl_DoubleRatchetState__receiving_message_number__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_receiving_message_number =
  impl_DoubleRatchetState__receiving_message_number__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_receiving_message_number'

assume
val impl_DoubleRatchetState__receiving_message_number__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_receiving_message_number__e_': Prims.unit

unfold
let
impl_DoubleRatchetState__receiving_message_number__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_receiving_message_number__e_ =
  impl_DoubleRatchetState__receiving_message_number__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_receiving_message_number__e_'

assume
val impl_DoubleRatchetState__skipped_keys_count__e_': Prims.unit

unfold
let impl_DoubleRatchetState__skipped_keys_count__e_ =
  impl_DoubleRatchetState__skipped_keys_count__e_'

assume
val impl_DoubleRatchetState__skipped_keys_count__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_skipped_keys_count':
    me: u32
  -> Wasm_bindgen.Convert.Traits.t_WasmRet u32

unfold
let
impl_DoubleRatchetState__skipped_keys_count__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_skipped_keys_count =
  impl_DoubleRatchetState__skipped_keys_count__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_skipped_keys_count'

assume
val impl_DoubleRatchetState__skipped_keys_count__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_skipped_keys_count__e_': Prims.unit

unfold
let
impl_DoubleRatchetState__skipped_keys_count__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_skipped_keys_count__e_ =
  impl_DoubleRatchetState__skipped_keys_count__e___e_ee_wasm_bindgen_generated_DoubleRatchetState_skipped_keys_count__e_'

type t_DoubleRatchetMessage = {
  f_ciphertext:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global;
  f_dh_public_key:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global;
  f_message_number:u32;
  f_previous_chain_length:u32
}

let impl_36: Core_models.Clone.t_Clone t_DoubleRatchetMessage =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_37': Core_models.Fmt.t_Debug t_DoubleRatchetMessage

unfold
let impl_37 = impl_37'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_19': Wasm_bindgen.__rt.Marker.t_SupportsConstructor t_DoubleRatchetMessage

unfold
let impl_19 = impl_19'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_20': Wasm_bindgen.__rt.Marker.t_SupportsInstanceProperty t_DoubleRatchetMessage

unfold
let impl_20 = impl_20'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_21': Wasm_bindgen.__rt.Marker.t_SupportsStaticProperty t_DoubleRatchetMessage

unfold
let impl_21 = impl_21'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_22': Wasm_bindgen.Describe.t_WasmDescribe t_DoubleRatchetMessage

unfold
let impl_22 = impl_22'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_23': Wasm_bindgen.Convert.Traits.t_IntoWasmAbi t_DoubleRatchetMessage

unfold
let impl_23 = impl_23'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_24': Wasm_bindgen.Convert.Traits.t_FromWasmAbi t_DoubleRatchetMessage

unfold
let impl_24 = impl_24'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_25': Core_models.Convert.t_From Wasm_bindgen.t_JsValue t_DoubleRatchetMessage

unfold
let impl_25 = impl_25'

assume
val f_from__impl_25__e_ee_wbg_doubleratchetmessage_new': u32 -> u32

unfold
let f_from__impl_25__e_ee_wbg_doubleratchetmessage_new =
  f_from__impl_25__e_ee_wbg_doubleratchetmessage_new'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_26': Wasm_bindgen.Convert.Traits.t_RefFromWasmAbi t_DoubleRatchetMessage

unfold
let impl_26 = impl_26'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_27': Wasm_bindgen.Convert.Traits.t_RefMutFromWasmAbi t_DoubleRatchetMessage

unfold
let impl_27 = impl_27'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_28': Wasm_bindgen.Convert.Traits.t_LongRefFromWasmAbi t_DoubleRatchetMessage

unfold
let impl_28 = impl_28'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_29': Wasm_bindgen.Convert.Traits.t_OptionIntoWasmAbi t_DoubleRatchetMessage

unfold
let impl_29 = impl_29'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_30': Wasm_bindgen.Convert.Traits.t_OptionFromWasmAbi t_DoubleRatchetMessage

unfold
let impl_30 = impl_30'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_31': Wasm_bindgen.Convert.Traits.t_TryFromJsValue t_DoubleRatchetMessage

unfold
let impl_31 = impl_31'

assume
val f_try_from_js_value__impl_31__e_ee_wbg_doubleratchetmessage_unwrap': u32 -> u32

unfold
let f_try_from_js_value__impl_31__e_ee_wbg_doubleratchetmessage_unwrap =
  f_try_from_js_value__impl_31__e_ee_wbg_doubleratchetmessage_unwrap'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_32': Wasm_bindgen.Describe.t_WasmDescribeVector t_DoubleRatchetMessage

unfold
let impl_32 = impl_32'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_33': Wasm_bindgen.Convert.Traits.t_VectorIntoWasmAbi t_DoubleRatchetMessage

unfold
let impl_33 = impl_33'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_34': Wasm_bindgen.Convert.Traits.t_VectorFromWasmAbi t_DoubleRatchetMessage

unfold
let impl_34 = impl_34'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_35': Wasm_bindgen.__rt.t_VectorIntoJsValue t_DoubleRatchetMessage

unfold
let impl_35 = impl_35'

let impl_DoubleRatchetMessage__ciphertext (self: t_DoubleRatchetMessage) : Js_sys.t_Uint8Array =
  Core_models.Convert.f_from #Js_sys.t_Uint8Array
    #(t_Slice u8)
    #FStar.Tactics.Typeclasses.solve
    (self.f_ciphertext.[ Core_models.Ops.Range.RangeFull <: Core_models.Ops.Range.t_RangeFull ]
      <:
      t_Slice u8)

let impl_DoubleRatchetMessage__dh_public_key (self: t_DoubleRatchetMessage) : Js_sys.t_Uint8Array =
  Core_models.Convert.f_from #Js_sys.t_Uint8Array
    #(t_Slice u8)
    #FStar.Tactics.Typeclasses.solve
    (self.f_dh_public_key.[ Core_models.Ops.Range.RangeFull <: Core_models.Ops.Range.t_RangeFull ]
      <:
      t_Slice u8)

let impl_DoubleRatchetMessage__message_number (self: t_DoubleRatchetMessage) : u32 =
  self.f_message_number

let impl_DoubleRatchetMessage__previous_chain_length (self: t_DoubleRatchetMessage) : u32 =
  self.f_previous_chain_length

assume
val impl_DoubleRatchetMessage__ciphertext__e_': Prims.unit

unfold
let impl_DoubleRatchetMessage__ciphertext__e_ = impl_DoubleRatchetMessage__ciphertext__e_'

assume
val impl_DoubleRatchetMessage__ciphertext__e___e_ee_wasm_bindgen_generated_DoubleRatchetMessage_ciphertext':
    me: u32
  -> Wasm_bindgen.Convert.Traits.t_WasmRet u32

unfold
let
impl_DoubleRatchetMessage__ciphertext__e___e_ee_wasm_bindgen_generated_DoubleRatchetMessage_ciphertext =
  impl_DoubleRatchetMessage__ciphertext__e___e_ee_wasm_bindgen_generated_DoubleRatchetMessage_ciphertext'

assume
val impl_DoubleRatchetMessage__ciphertext__e___e_ee_wasm_bindgen_generated_DoubleRatchetMessage_ciphertext__e_': Prims.unit

unfold
let
impl_DoubleRatchetMessage__ciphertext__e___e_ee_wasm_bindgen_generated_DoubleRatchetMessage_ciphertext__e_ =
  impl_DoubleRatchetMessage__ciphertext__e___e_ee_wasm_bindgen_generated_DoubleRatchetMessage_ciphertext__e_'

assume
val impl_DoubleRatchetMessage__dh_public_key__e_': Prims.unit

unfold
let impl_DoubleRatchetMessage__dh_public_key__e_ = impl_DoubleRatchetMessage__dh_public_key__e_'

assume
val impl_DoubleRatchetMessage__dh_public_key__e___e_ee_wasm_bindgen_generated_DoubleRatchetMessage_dh_public_key':
    me: u32
  -> Wasm_bindgen.Convert.Traits.t_WasmRet u32

unfold
let
impl_DoubleRatchetMessage__dh_public_key__e___e_ee_wasm_bindgen_generated_DoubleRatchetMessage_dh_public_key =
  impl_DoubleRatchetMessage__dh_public_key__e___e_ee_wasm_bindgen_generated_DoubleRatchetMessage_dh_public_key'

assume
val impl_DoubleRatchetMessage__dh_public_key__e___e_ee_wasm_bindgen_generated_DoubleRatchetMessage_dh_public_key__e_': Prims.unit

unfold
let
impl_DoubleRatchetMessage__dh_public_key__e___e_ee_wasm_bindgen_generated_DoubleRatchetMessage_dh_public_key__e_ =
  impl_DoubleRatchetMessage__dh_public_key__e___e_ee_wasm_bindgen_generated_DoubleRatchetMessage_dh_public_key__e_'

assume
val impl_DoubleRatchetMessage__message_number__e_': Prims.unit

unfold
let impl_DoubleRatchetMessage__message_number__e_ = impl_DoubleRatchetMessage__message_number__e_'

assume
val impl_DoubleRatchetMessage__message_number__e___e_ee_wasm_bindgen_generated_DoubleRatchetMessage_message_number':
    me: u32
  -> Wasm_bindgen.Convert.Traits.t_WasmRet u32

unfold
let
impl_DoubleRatchetMessage__message_number__e___e_ee_wasm_bindgen_generated_DoubleRatchetMessage_message_number =
  impl_DoubleRatchetMessage__message_number__e___e_ee_wasm_bindgen_generated_DoubleRatchetMessage_message_number'

assume
val impl_DoubleRatchetMessage__message_number__e___e_ee_wasm_bindgen_generated_DoubleRatchetMessage_message_number__e_': Prims.unit

unfold
let
impl_DoubleRatchetMessage__message_number__e___e_ee_wasm_bindgen_generated_DoubleRatchetMessage_message_number__e_ =
  impl_DoubleRatchetMessage__message_number__e___e_ee_wasm_bindgen_generated_DoubleRatchetMessage_message_number__e_'

assume
val impl_DoubleRatchetMessage__previous_chain_length__e_': Prims.unit

unfold
let impl_DoubleRatchetMessage__previous_chain_length__e_ =
  impl_DoubleRatchetMessage__previous_chain_length__e_'

assume
val impl_DoubleRatchetMessage__previous_chain_length__e___e_ee_wasm_bindgen_generated_DoubleRatchetMessage_previous_chain_length':
    me: u32
  -> Wasm_bindgen.Convert.Traits.t_WasmRet u32

unfold
let
impl_DoubleRatchetMessage__previous_chain_length__e___e_ee_wasm_bindgen_generated_DoubleRatchetMessage_previous_chain_length =
  impl_DoubleRatchetMessage__previous_chain_length__e___e_ee_wasm_bindgen_generated_DoubleRatchetMessage_previous_chain_length'

assume
val impl_DoubleRatchetMessage__previous_chain_length__e___e_ee_wasm_bindgen_generated_DoubleRatchetMessage_previous_chain_length__e_': Prims.unit

unfold
let
impl_DoubleRatchetMessage__previous_chain_length__e___e_ee_wasm_bindgen_generated_DoubleRatchetMessage_previous_chain_length__e_ =
  impl_DoubleRatchetMessage__previous_chain_length__e___e_ee_wasm_bindgen_generated_DoubleRatchetMessage_previous_chain_length__e_'

let initialize_double_ratchet (shared_secret: Js_sys.t_Uint8Array) (is_initiator: bool)
    : Core_models.Result.t_Result t_DoubleRatchetState Wasm_bindgen.t_JsValue =
  let args:bool = is_initiator <: bool in
  let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
    let list = [Core_models.Fmt.Rt.impl__new_display #bool args] in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
    Rust_primitives.Hax.array_of_list 1 list
  in
  let _:Prims.unit =
    log (Core_models.Ops.Deref.f_deref #Alloc.String.t_String
          #FStar.Tactics.Typeclasses.solve
          (Core_models.Hint.must_use #Alloc.String.t_String
              (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 2)
                      (mk_usize 1)
                      (let list = ["Initializing Double Ratchet (initiator: "; ")"] in
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
  let shared_secret_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Signal_protocol_wasm.Rust.Crypto.uint8_array_to_vec shared_secret
  in
  Core_models.Result.impl__map_err #t_DoubleRatchetState
    #Signal_protocol_core.Error.t_SignalError
    #Wasm_bindgen.t_JsValue
    #(Signal_protocol_core.Error.t_SignalError -> Wasm_bindgen.t_JsValue)
    (Core_models.Result.impl__map #Signal_protocol_core.Double_ratchet.t_DoubleRatchetState
        #Signal_protocol_core.Error.t_SignalError
        #t_DoubleRatchetState
        #(Signal_protocol_core.Double_ratchet.t_DoubleRatchetState -> t_DoubleRatchetState)
        (Signal_protocol_core.Double_ratchet.initialize_double_ratchet_internal (Alloc.Vec.impl_1__as_slice
                shared_secret_bytes
              <:
              t_Slice u8)
            is_initiator
          <:
          Core_models.Result.t_Result Signal_protocol_core.Double_ratchet.t_DoubleRatchetState
            Signal_protocol_core.Error.t_SignalError)
        core_to_wasm_state
      <:
      Core_models.Result.t_Result t_DoubleRatchetState Signal_protocol_core.Error.t_SignalError)
    (fun e ->
        let e:Signal_protocol_core.Error.t_SignalError = e in
        Wasm_bindgen.impl_JsValue__from_str (Core_models.Ops.Deref.f_deref #Alloc.String.t_String
              #FStar.Tactics.Typeclasses.solve
              (Alloc.String.f_to_string #Signal_protocol_core.Error.t_SignalError
                  #FStar.Tactics.Typeclasses.solve
                  e
                <:
                Alloc.String.t_String)
            <:
            string)
        <:
        Wasm_bindgen.t_JsValue)

assume
val e_': Prims.unit

unfold
let e_ = e_'

assume
val e___e_ee_wasm_bindgen_generated_initialize_double_ratchet':
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
let e___e_ee_wasm_bindgen_generated_initialize_double_ratchet =
  e___e_ee_wasm_bindgen_generated_initialize_double_ratchet'

assume
val e___e_ee_wasm_bindgen_generated_initialize_double_ratchet__e_': Prims.unit

unfold
let e___e_ee_wasm_bindgen_generated_initialize_double_ratchet__e_ =
  e___e_ee_wasm_bindgen_generated_initialize_double_ratchet__e_'

/// Derive a message key from a chain key - delegates to core (for tests)
let derive_message_key (chain_key: t_Slice u8)
    : Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      Signal_protocol_core.Error.t_SignalError =
  Signal_protocol_core.Double_ratchet.derive_message_key chain_key

/// Derive the next chain key - delegates to core (for tests)
let derive_next_chain_key (chain_key: t_Slice u8)
    : Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      Signal_protocol_core.Error.t_SignalError =
  Signal_protocol_core.Double_ratchet.derive_next_chain_key chain_key

let double_ratchet_encrypt (state: t_DoubleRatchetState) (plaintext: Js_sys.t_Uint8Array)
    : (t_DoubleRatchetState &
      Core_models.Result.t_Result t_DoubleRatchetMessage Wasm_bindgen.t_JsValue) =
  let args:u32 = state.f_sending_message_number <: u32 in
  let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
    let list = [Core_models.Fmt.Rt.impl__new_display #u32 args] in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
    Rust_primitives.Hax.array_of_list 1 list
  in
  let _:Prims.unit =
    log (Core_models.Ops.Deref.f_deref #Alloc.String.t_String
          #FStar.Tactics.Typeclasses.solve
          (Core_models.Hint.must_use #Alloc.String.t_String
              (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                      (mk_usize 1)
                      (let list = ["Encrypting message #"] in
                        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                        Rust_primitives.Hax.array_of_list 1 list)
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
  let plaintext_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Signal_protocol_wasm.Rust.Crypto.uint8_array_to_vec plaintext
  in
  let core_state:Signal_protocol_core.Double_ratchet.t_DoubleRatchetState =
    wasm_to_core_state state
  in
  let
  (tmp0: Signal_protocol_core.Double_ratchet.t_DoubleRatchetState),
  (out:
    Core_models.Result.t_Result Signal_protocol_core.Double_ratchet.t_DoubleRatchetMessage
      Signal_protocol_core.Error.t_SignalError) =
    Signal_protocol_core.Double_ratchet.double_ratchet_encrypt_internal core_state
      (Alloc.Vec.impl_1__as_slice plaintext_bytes <: t_Slice u8)
  in
  let core_state:Signal_protocol_core.Double_ratchet.t_DoubleRatchetState = tmp0 in
  match
    Core_models.Result.impl__map_err #Signal_protocol_core.Double_ratchet.t_DoubleRatchetMessage
      #Signal_protocol_core.Error.t_SignalError
      #Wasm_bindgen.t_JsValue
      #(Signal_protocol_core.Error.t_SignalError -> Wasm_bindgen.t_JsValue)
      out
      (fun e ->
          let e:Signal_protocol_core.Error.t_SignalError = e in
          Wasm_bindgen.impl_JsValue__from_str (Core_models.Ops.Deref.f_deref #Alloc.String.t_String
                #FStar.Tactics.Typeclasses.solve
                (Alloc.String.f_to_string #Signal_protocol_core.Error.t_SignalError
                    #FStar.Tactics.Typeclasses.solve
                    e
                  <:
                  Alloc.String.t_String)
              <:
              string)
          <:
          Wasm_bindgen.t_JsValue)
    <:
    Core_models.Result.t_Result Signal_protocol_core.Double_ratchet.t_DoubleRatchetMessage
      Wasm_bindgen.t_JsValue
  with
  | Core_models.Result.Result_Ok core_msg ->
    let state:t_DoubleRatchetState = core_to_wasm_state core_state in
    let hax_temp_output:Core_models.Result.t_Result t_DoubleRatchetMessage Wasm_bindgen.t_JsValue =
      Core_models.Result.Result_Ok
      ({
          f_ciphertext = core_msg.Signal_protocol_core.Double_ratchet.f_ciphertext;
          f_dh_public_key = core_msg.Signal_protocol_core.Double_ratchet.f_dh_public_key;
          f_message_number = core_msg.Signal_protocol_core.Double_ratchet.f_message_number;
          f_previous_chain_length
          =
          core_msg.Signal_protocol_core.Double_ratchet.f_previous_chain_length
        }
        <:
        t_DoubleRatchetMessage)
      <:
      Core_models.Result.t_Result t_DoubleRatchetMessage Wasm_bindgen.t_JsValue
    in
    state, hax_temp_output
    <:
    (t_DoubleRatchetState &
      Core_models.Result.t_Result t_DoubleRatchetMessage Wasm_bindgen.t_JsValue)
  | Core_models.Result.Result_Err err ->
    state,
    (Core_models.Result.Result_Err err
      <:
      Core_models.Result.t_Result t_DoubleRatchetMessage Wasm_bindgen.t_JsValue)
    <:
    (t_DoubleRatchetState &
      Core_models.Result.t_Result t_DoubleRatchetMessage Wasm_bindgen.t_JsValue)

assume
val e_ee_1': Prims.unit

unfold
let e_ee_1 = e_ee_1'

assume
val e_ee_1__e_ee_wasm_bindgen_generated_double_ratchet_encrypt':
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
let e_ee_1__e_ee_wasm_bindgen_generated_double_ratchet_encrypt =
  e_ee_1__e_ee_wasm_bindgen_generated_double_ratchet_encrypt'

assume
val e_ee_1__e_ee_wasm_bindgen_generated_double_ratchet_encrypt__e_': Prims.unit

unfold
let e_ee_1__e_ee_wasm_bindgen_generated_double_ratchet_encrypt__e_ =
  e_ee_1__e_ee_wasm_bindgen_generated_double_ratchet_encrypt__e_'

let double_ratchet_decrypt (state: t_DoubleRatchetState) (message: t_DoubleRatchetMessage)
    : (t_DoubleRatchetState & Core_models.Result.t_Result Js_sys.t_Uint8Array Wasm_bindgen.t_JsValue
    ) =
  let args:u32 = message.f_message_number <: u32 in
  let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
    let list = [Core_models.Fmt.Rt.impl__new_display #u32 args] in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
    Rust_primitives.Hax.array_of_list 1 list
  in
  let _:Prims.unit =
    log (Core_models.Ops.Deref.f_deref #Alloc.String.t_String
          #FStar.Tactics.Typeclasses.solve
          (Core_models.Hint.must_use #Alloc.String.t_String
              (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                      (mk_usize 1)
                      (let list = ["Decrypting message #"] in
                        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                        Rust_primitives.Hax.array_of_list 1 list)
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
  let core_msg:Signal_protocol_core.Double_ratchet.t_DoubleRatchetMessage =
    {
      Signal_protocol_core.Double_ratchet.f_ciphertext
      =
      Core_models.Clone.f_clone #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        message.f_ciphertext;
      Signal_protocol_core.Double_ratchet.f_dh_public_key
      =
      Core_models.Clone.f_clone #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        message.f_dh_public_key;
      Signal_protocol_core.Double_ratchet.f_message_number = message.f_message_number;
      Signal_protocol_core.Double_ratchet.f_previous_chain_length = message.f_previous_chain_length
    }
    <:
    Signal_protocol_core.Double_ratchet.t_DoubleRatchetMessage
  in
  let core_state:Signal_protocol_core.Double_ratchet.t_DoubleRatchetState =
    wasm_to_core_state state
  in
  let
  (tmp0: Signal_protocol_core.Double_ratchet.t_DoubleRatchetState),
  (out:
    Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      Signal_protocol_core.Error.t_SignalError) =
    Signal_protocol_core.Double_ratchet.double_ratchet_decrypt_internal core_state core_msg
  in
  let core_state:Signal_protocol_core.Double_ratchet.t_DoubleRatchetState = tmp0 in
  match
    Core_models.Result.impl__map_err #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      #Signal_protocol_core.Error.t_SignalError
      #Wasm_bindgen.t_JsValue
      #(Signal_protocol_core.Error.t_SignalError -> Wasm_bindgen.t_JsValue)
      out
      (fun e ->
          let e:Signal_protocol_core.Error.t_SignalError = e in
          Wasm_bindgen.impl_JsValue__from_str (Core_models.Ops.Deref.f_deref #Alloc.String.t_String
                #FStar.Tactics.Typeclasses.solve
                (Alloc.String.f_to_string #Signal_protocol_core.Error.t_SignalError
                    #FStar.Tactics.Typeclasses.solve
                    e
                  <:
                  Alloc.String.t_String)
              <:
              string)
          <:
          Wasm_bindgen.t_JsValue)
    <:
    Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Wasm_bindgen.t_JsValue
  with
  | Core_models.Result.Result_Ok plaintext ->
    let state:t_DoubleRatchetState = core_to_wasm_state core_state in
    let hax_temp_output:Core_models.Result.t_Result Js_sys.t_Uint8Array Wasm_bindgen.t_JsValue =
      Core_models.Result.Result_Ok
      (Core_models.Convert.f_from #Js_sys.t_Uint8Array
          #(t_Slice u8)
          #FStar.Tactics.Typeclasses.solve
          (plaintext.[ Core_models.Ops.Range.RangeFull <: Core_models.Ops.Range.t_RangeFull ]
            <:
            t_Slice u8))
      <:
      Core_models.Result.t_Result Js_sys.t_Uint8Array Wasm_bindgen.t_JsValue
    in
    state, hax_temp_output
    <:
    (t_DoubleRatchetState & Core_models.Result.t_Result Js_sys.t_Uint8Array Wasm_bindgen.t_JsValue)
  | Core_models.Result.Result_Err err ->
    state,
    (Core_models.Result.Result_Err err
      <:
      Core_models.Result.t_Result Js_sys.t_Uint8Array Wasm_bindgen.t_JsValue)
    <:
    (t_DoubleRatchetState & Core_models.Result.t_Result Js_sys.t_Uint8Array Wasm_bindgen.t_JsValue)

assume
val e_ee_2': Prims.unit

unfold
let e_ee_2 = e_ee_2'

assume
val e_ee_2__e_ee_wasm_bindgen_generated_double_ratchet_decrypt':
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
let e_ee_2__e_ee_wasm_bindgen_generated_double_ratchet_decrypt =
  e_ee_2__e_ee_wasm_bindgen_generated_double_ratchet_decrypt'

assume
val e_ee_2__e_ee_wasm_bindgen_generated_double_ratchet_decrypt__e_': Prims.unit

unfold
let e_ee_2__e_ee_wasm_bindgen_generated_double_ratchet_decrypt__e_ =
  e_ee_2__e_ee_wasm_bindgen_generated_double_ratchet_decrypt__e_'

let cleanup_skipped_message_keys (state: t_DoubleRatchetState) (max_keys: usize)
    : (t_DoubleRatchetState & usize) =
  let args:usize = max_keys <: usize in
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
                      (let list = ["Cleaning up skipped message keys (max: "; ")"] in
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
  let core_state:Signal_protocol_core.Double_ratchet.t_DoubleRatchetState =
    wasm_to_core_state state
  in
  let (tmp0: Signal_protocol_core.Double_ratchet.t_DoubleRatchetState), (out: usize) =
    Signal_protocol_core.Double_ratchet.cleanup_skipped_message_keys_internal core_state max_keys
  in
  let core_state:Signal_protocol_core.Double_ratchet.t_DoubleRatchetState = tmp0 in
  let removed:usize = out in
  let state:t_DoubleRatchetState = core_to_wasm_state core_state in
  let hax_temp_output:usize = removed in
  state, hax_temp_output <: (t_DoubleRatchetState & usize)

assume
val e_ee_3': Prims.unit

unfold
let e_ee_3 = e_ee_3'

assume
val e_ee_3__e_ee_wasm_bindgen_generated_cleanup_skipped_message_keys':
    arg0_1_: u32 ->
    arg0_2_: Prims.unit ->
    arg0_3_: Prims.unit ->
    arg0_4_: Prims.unit ->
    arg1_1_: u32 ->
    arg1_2_: Prims.unit ->
    arg1_3_: Prims.unit ->
    arg1_4_: Prims.unit
  -> Wasm_bindgen.Convert.Traits.t_WasmRet u32

unfold
let e_ee_3__e_ee_wasm_bindgen_generated_cleanup_skipped_message_keys =
  e_ee_3__e_ee_wasm_bindgen_generated_cleanup_skipped_message_keys'

assume
val e_ee_3__e_ee_wasm_bindgen_generated_cleanup_skipped_message_keys__e_': Prims.unit

unfold
let e_ee_3__e_ee_wasm_bindgen_generated_cleanup_skipped_message_keys__e_ =
  e_ee_3__e_ee_wasm_bindgen_generated_cleanup_skipped_message_keys__e_'

/// Perform DH ratchet step - delegates to core (for tests)
let perform_dh_ratchet_step (state: t_DoubleRatchetState) (new_remote_public_key: t_Slice u8)
    : (t_DoubleRatchetState &
      Core_models.Result.t_Result Prims.unit Signal_protocol_core.Error.t_SignalError) =
  let core_state:Signal_protocol_core.Double_ratchet.t_DoubleRatchetState =
    wasm_to_core_state state
  in
  let
  (tmp0: Signal_protocol_core.Double_ratchet.t_DoubleRatchetState),
  (out: Core_models.Result.t_Result Prims.unit Signal_protocol_core.Error.t_SignalError) =
    Signal_protocol_core.Double_ratchet.perform_dh_ratchet_step core_state new_remote_public_key
  in
  let core_state:Signal_protocol_core.Double_ratchet.t_DoubleRatchetState = tmp0 in
  match out <: Core_models.Result.t_Result Prims.unit Signal_protocol_core.Error.t_SignalError with
  | Core_models.Result.Result_Ok _ ->
    let state:t_DoubleRatchetState = core_to_wasm_state core_state in
    let hax_temp_output:Core_models.Result.t_Result Prims.unit
      Signal_protocol_core.Error.t_SignalError =
      Core_models.Result.Result_Ok (() <: Prims.unit)
      <:
      Core_models.Result.t_Result Prims.unit Signal_protocol_core.Error.t_SignalError
    in
    state, hax_temp_output
    <:
    (t_DoubleRatchetState &
      Core_models.Result.t_Result Prims.unit Signal_protocol_core.Error.t_SignalError)
  | Core_models.Result.Result_Err err ->
    state,
    (Core_models.Result.Result_Err err
      <:
      Core_models.Result.t_Result Prims.unit Signal_protocol_core.Error.t_SignalError)
    <:
    (t_DoubleRatchetState &
      Core_models.Result.t_Result Prims.unit Signal_protocol_core.Error.t_SignalError)

/// Skip message keys - delegates to core (for tests)
let skip_message_keys (state: t_DoubleRatchetState) (until_message_number: u32)
    : (t_DoubleRatchetState &
      Core_models.Result.t_Result Prims.unit Signal_protocol_core.Error.t_SignalError) =
  let core_state:Signal_protocol_core.Double_ratchet.t_DoubleRatchetState =
    wasm_to_core_state state
  in
  let
  (tmp0: Signal_protocol_core.Double_ratchet.t_DoubleRatchetState),
  (out: Core_models.Result.t_Result Prims.unit Signal_protocol_core.Error.t_SignalError) =
    Signal_protocol_core.Double_ratchet.skip_message_keys core_state until_message_number
  in
  let core_state:Signal_protocol_core.Double_ratchet.t_DoubleRatchetState = tmp0 in
  match out <: Core_models.Result.t_Result Prims.unit Signal_protocol_core.Error.t_SignalError with
  | Core_models.Result.Result_Ok _ ->
    let state:t_DoubleRatchetState = core_to_wasm_state core_state in
    let hax_temp_output:Core_models.Result.t_Result Prims.unit
      Signal_protocol_core.Error.t_SignalError =
      Core_models.Result.Result_Ok (() <: Prims.unit)
      <:
      Core_models.Result.t_Result Prims.unit Signal_protocol_core.Error.t_SignalError
    in
    state, hax_temp_output
    <:
    (t_DoubleRatchetState &
      Core_models.Result.t_Result Prims.unit Signal_protocol_core.Error.t_SignalError)
  | Core_models.Result.Result_Err err ->
    state,
    (Core_models.Result.Result_Err err
      <:
      Core_models.Result.t_Result Prims.unit Signal_protocol_core.Error.t_SignalError)
    <:
    (t_DoubleRatchetState &
      Core_models.Result.t_Result Prims.unit Signal_protocol_core.Error.t_SignalError)

/// Cleanup skipped keys internal - delegates to core (for tests)
let cleanup_skipped_message_keys_internal (state: t_DoubleRatchetState) (max_keys: usize)
    : (t_DoubleRatchetState & usize) =
  let core_state:Signal_protocol_core.Double_ratchet.t_DoubleRatchetState =
    wasm_to_core_state state
  in
  let (tmp0: Signal_protocol_core.Double_ratchet.t_DoubleRatchetState), (out: usize) =
    Signal_protocol_core.Double_ratchet.cleanup_skipped_message_keys_internal core_state max_keys
  in
  let core_state:Signal_protocol_core.Double_ratchet.t_DoubleRatchetState = tmp0 in
  let removed:usize = out in
  let state:t_DoubleRatchetState = core_to_wasm_state core_state in
  let hax_temp_output:usize = removed in
  state, hax_temp_output <: (t_DoubleRatchetState & usize)

/// Internal version for native testing - delegates to core
let initialize_double_ratchet_internal (shared_secret: t_Slice u8) (is_initiator: bool)
    : Core_models.Result.t_Result t_DoubleRatchetState Signal_protocol_core.Error.t_SignalError =
  Core_models.Result.impl__map #Signal_protocol_core.Double_ratchet.t_DoubleRatchetState
    #Signal_protocol_core.Error.t_SignalError
    #t_DoubleRatchetState
    #(Signal_protocol_core.Double_ratchet.t_DoubleRatchetState -> t_DoubleRatchetState)
    (Signal_protocol_core.Double_ratchet.initialize_double_ratchet_internal shared_secret
        is_initiator
      <:
      Core_models.Result.t_Result Signal_protocol_core.Double_ratchet.t_DoubleRatchetState
        Signal_protocol_core.Error.t_SignalError)
    core_to_wasm_state

/// Internal encrypt for native testing - delegates to core
let double_ratchet_encrypt_internal (state: t_DoubleRatchetState) (plaintext: t_Slice u8)
    : (t_DoubleRatchetState &
      Core_models.Result.t_Result t_DoubleRatchetMessage Signal_protocol_core.Error.t_SignalError) =
  let core_state:Signal_protocol_core.Double_ratchet.t_DoubleRatchetState =
    wasm_to_core_state state
  in
  let
  (tmp0: Signal_protocol_core.Double_ratchet.t_DoubleRatchetState),
  (out:
    Core_models.Result.t_Result Signal_protocol_core.Double_ratchet.t_DoubleRatchetMessage
      Signal_protocol_core.Error.t_SignalError) =
    Signal_protocol_core.Double_ratchet.double_ratchet_encrypt_internal core_state plaintext
  in
  let core_state:Signal_protocol_core.Double_ratchet.t_DoubleRatchetState = tmp0 in
  match
    out
    <:
    Core_models.Result.t_Result Signal_protocol_core.Double_ratchet.t_DoubleRatchetMessage
      Signal_protocol_core.Error.t_SignalError
  with
  | Core_models.Result.Result_Ok core_msg ->
    let state:t_DoubleRatchetState = core_to_wasm_state core_state in
    let hax_temp_output:Core_models.Result.t_Result t_DoubleRatchetMessage
      Signal_protocol_core.Error.t_SignalError =
      Core_models.Result.Result_Ok
      ({
          f_ciphertext = core_msg.Signal_protocol_core.Double_ratchet.f_ciphertext;
          f_dh_public_key = core_msg.Signal_protocol_core.Double_ratchet.f_dh_public_key;
          f_message_number = core_msg.Signal_protocol_core.Double_ratchet.f_message_number;
          f_previous_chain_length
          =
          core_msg.Signal_protocol_core.Double_ratchet.f_previous_chain_length
        }
        <:
        t_DoubleRatchetMessage)
      <:
      Core_models.Result.t_Result t_DoubleRatchetMessage Signal_protocol_core.Error.t_SignalError
    in
    state, hax_temp_output
    <:
    (t_DoubleRatchetState &
      Core_models.Result.t_Result t_DoubleRatchetMessage Signal_protocol_core.Error.t_SignalError)
  | Core_models.Result.Result_Err err ->
    state,
    (Core_models.Result.Result_Err err
      <:
      Core_models.Result.t_Result t_DoubleRatchetMessage Signal_protocol_core.Error.t_SignalError)
    <:
    (t_DoubleRatchetState &
      Core_models.Result.t_Result t_DoubleRatchetMessage Signal_protocol_core.Error.t_SignalError)

/// Internal decrypt for native testing - delegates to core
let double_ratchet_decrypt_internal (state: t_DoubleRatchetState) (message: t_DoubleRatchetMessage)
    : (t_DoubleRatchetState &
      Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        Signal_protocol_core.Error.t_SignalError) =
  let core_msg:Signal_protocol_core.Double_ratchet.t_DoubleRatchetMessage =
    {
      Signal_protocol_core.Double_ratchet.f_ciphertext
      =
      Core_models.Clone.f_clone #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        message.f_ciphertext;
      Signal_protocol_core.Double_ratchet.f_dh_public_key
      =
      Core_models.Clone.f_clone #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        message.f_dh_public_key;
      Signal_protocol_core.Double_ratchet.f_message_number = message.f_message_number;
      Signal_protocol_core.Double_ratchet.f_previous_chain_length = message.f_previous_chain_length
    }
    <:
    Signal_protocol_core.Double_ratchet.t_DoubleRatchetMessage
  in
  let core_state:Signal_protocol_core.Double_ratchet.t_DoubleRatchetState =
    wasm_to_core_state state
  in
  let
  (tmp0: Signal_protocol_core.Double_ratchet.t_DoubleRatchetState),
  (out:
    Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      Signal_protocol_core.Error.t_SignalError) =
    Signal_protocol_core.Double_ratchet.double_ratchet_decrypt_internal core_state core_msg
  in
  let core_state:Signal_protocol_core.Double_ratchet.t_DoubleRatchetState = tmp0 in
  match
    out
    <:
    Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      Signal_protocol_core.Error.t_SignalError
  with
  | Core_models.Result.Result_Ok plaintext ->
    let state:t_DoubleRatchetState = core_to_wasm_state core_state in
    let hax_temp_output:Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      Signal_protocol_core.Error.t_SignalError =
      Core_models.Result.Result_Ok plaintext
      <:
      Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        Signal_protocol_core.Error.t_SignalError
    in
    state, hax_temp_output
    <:
    (t_DoubleRatchetState &
      Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        Signal_protocol_core.Error.t_SignalError)
  | Core_models.Result.Result_Err err ->
    state,
    (Core_models.Result.Result_Err err
      <:
      Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        Signal_protocol_core.Error.t_SignalError)
    <:
    (t_DoubleRatchetState &
      Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        Signal_protocol_core.Error.t_SignalError)
