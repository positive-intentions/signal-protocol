module Signal_protocol_wasm
#set-options "--fuel 0 --ifuel 1 --z3rlimit 40"
open FStar.Mul
open Core_models

/// Initialize the WASM module
///
/// This function is automatically called when the WASM module is loaded.
/// It sets up error handling and logging for better debugging experience.
let main (_: Prims.unit) : Prims.unit =
  let _:Prims.unit =
    Web_sys.Features.Gen_console.Console.log_1_ (Wasm_bindgen.impl_JsValue__from_str "Signal Protocol WASM module initialized"

        <:
        Wasm_bindgen.t_JsValue)
  in
  let _:Prims.unit = Console_error_panic_hook.set_once () in
  ()

assume
val e_': Prims.unit

unfold
let e_ = e_'

/// Initialize the WASM module
///
/// This function is automatically called when the WASM module is loaded.
/// It sets up error handling and logging for better debugging experience.
assume
val e___e_ee_wasm_bindgen_generated_main': Prims.unit
  -> Wasm_bindgen.Convert.Traits.t_WasmRet Prims.unit

unfold
let e___e_ee_wasm_bindgen_generated_main = e___e_ee_wasm_bindgen_generated_main'

assume
val e___e_ee_wasm_bindgen_generated_main__e_': Prims.unit

unfold
let e___e_ee_wasm_bindgen_generated_main__e_ = e___e_ee_wasm_bindgen_generated_main__e_'

assume
val e___e_ee_wasm_bindgen_generated_main__e___e_ASSERT': Prims.unit -> Prims.unit

unfold
let e___e_ee_wasm_bindgen_generated_main__e___e_ASSERT =
  e___e_ee_wasm_bindgen_generated_main__e___e_ASSERT'
