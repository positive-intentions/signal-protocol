module Core_models.Iter.Adapters.Cloned
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Rust_primitives

type t_Cloned (v_I: Type0) = v_I
