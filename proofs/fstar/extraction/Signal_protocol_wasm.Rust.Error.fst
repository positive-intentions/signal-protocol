module Signal_protocol_wasm.Rust.Error
#set-options "--fuel 0 --ifuel 1 --z3rlimit 40"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Signal_protocol_core.Error in
  ()

/// Convert SignalError to JavaScript-compatible JsValue (orphan rule prevents From impl)
let signal_error_to_js_value (err: Signal_protocol_core.Error.t_SignalError)
    : Wasm_bindgen.t_JsValue =
  Wasm_bindgen.impl_JsValue__from_str (Core_models.Ops.Deref.f_deref #Alloc.String.t_String
        #FStar.Tactics.Typeclasses.solve
        (Alloc.String.f_to_string #Signal_protocol_core.Error.t_SignalError
            #FStar.Tactics.Typeclasses.solve
            err
          <:
          Alloc.String.t_String)
      <:
      string)
