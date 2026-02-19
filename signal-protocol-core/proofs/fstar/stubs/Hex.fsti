module Hex
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Rust_primitives

val encode: #a: Type0 -> a -> Prims.Pure Alloc.String.t_String Prims.l_True (fun _ -> Prims.l_True)
