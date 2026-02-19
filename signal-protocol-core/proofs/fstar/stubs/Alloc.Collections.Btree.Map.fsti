module Alloc.Collections.Btree.Map
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Rust_primitives

val t_BTreeMap (v_K v_V v_Alloc: Type0) : eqtype

val t_Keys (v_K: Type0) : Type0

val impl_18__new: #v_K: Type0 -> #v_V: Type0 -> #v_Alloc: Type0 -> Prims.unit
  -> Prims.Pure (t_BTreeMap v_K v_V v_Alloc) Prims.l_True (fun _ -> Prims.l_True)

val impl_20__insert: #v_K: Type0 -> #v_V: Type0 -> #v_Alloc: Type0 -> 
  t_BTreeMap v_K v_V v_Alloc -> v_K -> v_V
  -> Prims.Pure (t_BTreeMap v_K v_V v_Alloc) Prims.l_True (fun _ -> Prims.l_True)

val impl_20__remove: #v_K: Type0 -> #v_V: Type0 -> #v_Alloc: Type0 -> 
  t_BTreeMap v_K v_V v_Alloc -> v_K
  -> Prims.Pure (t_BTreeMap v_K v_V v_Alloc) Prims.l_True (fun _ -> Prims.l_True)

val impl_92__keys: #v_K: Type0 -> #v_V: Type0 -> #v_Alloc: Type0 -> 
  t_BTreeMap v_K v_V v_Alloc
  -> Prims.Pure (t_Keys v_K) Prims.l_True (fun _ -> Prims.l_True)

val impl_92__len: #v_K: Type0 -> #v_V: Type0 -> #v_Alloc: Type0 -> 
  t_BTreeMap v_K v_V v_Alloc
  -> Prims.Pure usize Prims.l_True (fun _ -> Prims.l_True)
