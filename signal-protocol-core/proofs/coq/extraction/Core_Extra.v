(** Core_Extra: Bridge between hax-generated Core library and Signal Protocol extraction.
    Provides definitions missing from the hax Core re-exports. *)

From Coq Require Import ZArith.
Require Import List.
Import List.ListNotations.
Open Scope Z_scope.
Open Scope bool_scope.
Require Import Ascii.
Require Import String.
Require Import Coq.Floats.Floats.
From RecordUpdate Require Import RecordSet.
Import RecordSetNotations.

(* Re-export the full Core library *)
From Core Require Import Core.
Export Core.

(* Re-export modules that Core.v does not transitively export *)

From Core Require Import Core_Slice.
Export Core_Slice.

(* Simple Result type without t_Sized constraints for easier type inference *)
Inductive t_Result (v_T : Type) (v_E : Type) : Type :=
| Result_Ok : v_T -> t_Result v_T v_E
| Result_Err : v_E -> t_Result v_T v_E.
Arguments Result_Ok {_ _}.
Arguments Result_Err {_ _}.

(* Unwrap helpers: In abstract crypto mode, some functions return Result but
   the extraction uses them as if they return plain values (no ? operator). *)
Axiom unwrap_ok : forall {A E : Type}, t_Result A E -> A.

(* ControlFlow - simplified without t_Sized constraints *)
Inductive t_ControlFlow (a : Type) (b : Type) :=
| ControlFlow_Continue : a -> t_ControlFlow a b
| ControlFlow_Break : b -> t_ControlFlow a b.
Arguments ControlFlow_Continue {_ _}.
Arguments ControlFlow_Break {_ _}.

Definition run {a : Type} (x : t_ControlFlow a a) : a :=
  match x with
  | ControlFlow_Continue v => v
  | ControlFlow_Break v => v
  end.

(* Override never_to_any to accept ControlFlow values as the early-return mechanism.
   In hax extraction, the pattern is:
     let hoist := ControlFlow_Break (...) in
     ControlFlow_Continue (never_to_any hoist)
   The outer `run` catches the Break. We make this opaque. *)
(* never_to_any' takes a ControlFlow and extracts the Continue value.
   The Break case is axiomatized as it represents unreachable code. *)
Axiom never_to_any' : forall {a b : Type}, t_ControlFlow a b -> a.



(* ===== Allocator and Vec ===== *)
Inductive globality := | t_Global.
Definition t_Vec (T : Type) (_ : globality) : Type := list T.

Definition impl__new {A : Type} '(_ : unit) : t_Vec A t_Global := nil.
Definition impl_1__push {A : Type} (l : t_Vec A t_Global) (x : A) : t_Vec A t_Global := app l [x].
Definition impl_1__len {A : Type} `{t_Sized A} `{t_Clone A} (l : t_Vec A t_Global) : t_usize :=
  impl__len (Build_t_Slice A l).
Definition impl_1__as_slice {A : Type} `{t_Sized A} (v : t_Vec A t_Global) : t_Slice A :=
  Build_t_Slice A v.
Definition impl_2__extend_from_slice {A : Type} (v : t_Vec A t_Global) (s : t_Slice A) : t_Vec A t_Global :=
  app v (Slice_f_v s).

Definition from_elem {A : Type} (x : A) (l : t_usize) : t_Vec A t_Global :=
  List.repeat x (N.to_nat (U64_f_v (usize_0 l))).

Definition impl__to_vec {A : Type} `{t_Sized A} (s : t_Slice A) : t_Vec A t_Global :=
  Slice_f_v s.

(* ===== BTreeMap (modeled as association list) ===== *)
Definition t_BTreeMap (K V : Type) (_ : globality) : Type := list (K * V).

Definition impl_18__new {K V : Type} '(_ : unit) : t_BTreeMap K V t_Global := nil.

Fixpoint btree_remove {K V : Type} `{t_PartialEq K K} (m : list (K * V)) (k : K) : list (K * V) * option V :=
  match m with
  | nil => (nil, None)
  | (k', v) :: rest =>
    if PartialEq_f_eq k k' then (rest, Some v)
    else let '(rest', found) := btree_remove rest k in ((k', v) :: rest', found)
  end.

Definition impl_20__insert {K V : Type} `{t_PartialEq K K} (m : t_BTreeMap K V t_Global) (k : K) (v : V) : t_BTreeMap K V t_Global * t_Option V :=
  let '(m', old) := btree_remove m k in
  let result := match old with
  | Some ov => Option_Some ov
  | None => Option_None
  end in
  ((k, v) :: m', result).

Definition impl_20__remove {K V : Type} `{t_PartialEq K K} (m : t_BTreeMap K V t_Global) (k : K) : t_BTreeMap K V t_Global * t_Option V :=
  let '(m', old) := btree_remove m k in
  let result := match old with
  | Some ov => Option_Some ov
  | None => Option_None
  end in
  (m', result).

Definition impl_92__len {K V : Type} `{t_Sized (K * V)} `{t_Clone (K * V)} (m : t_BTreeMap K V t_Global) : t_usize :=
  impl__len (Build_t_Slice (K * V)%type m).

Definition impl_92__keys {K V : Type} (m : t_BTreeMap K V t_Global) : list K :=
  List.map fst m.

(* ===== Short aliases for typeclass field accessors ===== *)
Definition f_ne {A B : Type} `{t_PartialEq A B} (x : A) (y : B) : bool := PartialEq_f_ne x y.
Definition f_eq' {A B : Type} `{t_PartialEq A B} (x : A) (y : B) : bool := PartialEq_f_eq x y.
Definition f_gt {A B : Type} `{t_PartialOrd A B} (x : A) (y : B) : bool := PartialOrd_f_gt x y.
Definition f_lt {A B : Type} `{t_PartialOrd A B} (x : A) (y : B) : bool := PartialOrd_f_lt x y.
Definition f_ge {A B : Type} `{t_PartialOrd A B} (x : A) (y : B) : bool := PartialOrd_f_ge x y.
Definition f_le {A B : Type} `{t_PartialOrd A B} (x : A) (y : B) : bool := PartialOrd_f_le x y.
Definition f_add {A B : Type} `{t_Add A B} (x : A) (y : B) := Add_f_add x y.
Definition f_sub {A B : Type} `{t_Sub A B} (x : A) (y : B) := Sub_f_sub x y.
Definition f_clone {A : Type} `{t_Clone A} (x : A) : A := Clone_f_clone x.

(* ===== Deref (coercion from Vec to Slice) ===== *)
Definition f_deref {A : Type} `{t_Sized A} (v : t_Vec A t_Global) : t_Slice A :=
  Build_t_Slice A v.

(* ===== Display, Error, Formatter stubs ===== *)
Definition t_Formatter : Type := unit.

Class t_Display (T : Type) : Type :=
  {
    implaabbcc_t_Display_f_fmt : T -> t_Formatter -> (t_Formatter * unit)
  }.

Class t_Error (T : Type) : Type := { }.

Definition impl__new_display {A : Type} `{t_Display A} (x : A) : string. exact ""%string. Defined.

Definition impl_1__new_v1 (pieces : list string) (args : list string) : string :=
  List.fold_left (fun acc s => String.append acc s) (pieces ++ args) ""%string.

Definition impl_11__write_fmt (f : t_Formatter) (s : string) : (t_Formatter * unit) :=
  (f, tt).

Definition format (s : string) : t_String := s.
Definition must_use {A : Type} (x : A) : A := x.

(* ===== Option extra methods ===== *)
(* Note: impl_1__is_some is already in Core_Option but we also need impl__is_some *)
Definition impl__is_some {A : Type} (o : t_Option A) : bool :=
  match o with
  | Option_Some _ => true
  | Option_None => false
  end.

Definition impl__as_ref {A : Type} (o : t_Option A) : t_Option A := o.

Definition impl__ok_or_else {A E : Type} (o : t_Option A) (f : unit -> E) : t_Result A E :=
  match o with
  | Option_Some x => Result_Ok x
  | Option_None => Result_Err (f tt)
  end.

(* ===== Try/Branch support (Result -> ControlFlow) ===== *)
Definition f_branch {T E : Type} (r : t_Result T E) : t_ControlFlow T (t_Result T E) :=
  match r with
  | Result_Ok v => ControlFlow_Continue v
  | Result_Err e => ControlFlow_Break (Result_Err e)
  end.

Definition f_from_residual {T E : Type} (r : t_Result T E) : t_Result T E := r.

(* ===== Range constructor alias ===== *)
Definition Range (start stop : t_usize) : t_Range t_usize :=
  Build_t_Range t_usize start stop.

(* ===== Sort stub ===== *)
Definition impl__sort {A : Type} `{t_Sized A} (s : t_Slice A) : t_Slice A := s.

(* ===== Iterator stubs ===== *)
Definition f_collect {A B : Type} (l : list A) : list A := l.
Definition f_cloned {A : Type} (l : list A) : list A := l.
Definition f_fold {A B : Type} (iter : list A) (init : B) (f : B -> A -> B) : B :=
  List.fold_left f iter init.
Definition f_into_iter {A : Type} (l : list A) : list A := l.
Definition f_take {A : Type} (l : list A) (n : t_usize) : list A :=
  List.firstn (N.to_nat (U64_f_v (usize_0 n))) l.

(* ===== Hex encoding stub ===== *)
Definition encode {A : Type} (x : A) : t_String := "hex"%string.

(* ===== Numeric conversions ===== *)
Definition cast {A B : Type} (x : A) : B. Admitted.
Definition impl_u32__to_be_bytes (x : t_u32) : list t_u8 :=
  [Build_t_u8 (Build_t_U8 0%N); Build_t_u8 (Build_t_U8 0%N);
   Build_t_u8 (Build_t_U8 0%N); Build_t_u8 (Build_t_U8 0%N)].

(* ===== String PartialEq instance ===== *)
#[global] Instance t_PartialEq_string : t_PartialEq string string :=
  {
    PartialEq_f_eq := String.eqb;
    PartialEq_f_ne := fun a b => negb (String.eqb a b);
  }.

(* ===== Display instances for numeric types ===== *)
#[global] Instance t_Display_usize : t_Display t_usize :=
  { implaabbcc_t_Display_f_fmt := fun _ f => (f, tt) }.
#[global] Instance t_Display_u32 : t_Display t_u32 :=
  { implaabbcc_t_Display_f_fmt := fun _ f => (f, tt) }.
#[global] Instance t_Display_string : t_Display string :=
  { implaabbcc_t_Display_f_fmt := fun _ f => (f, tt) }.
#[global] Instance t_Display_pair {A B} `{t_Display A} `{t_Display B} : t_Display (A * B) :=
  { implaabbcc_t_Display_f_fmt := fun _ f => (f, tt) }.

(* ===== RangeTo and RangeFrom for indexing ===== *)
Record t_RangeTo (T : Type) := RangeTo { RangeTo_f_end : T }.
Record t_RangeFrom (T : Type) := RangeFrom { RangeFrom_f_start : T }.
Arguments RangeTo {_}.
Arguments RangeFrom {_}.
Arguments RangeTo_f_end {_}.
Arguments RangeFrom_f_start {_}.

(* Overloaded f_index for different range types *)
Class Indexable (R : Type) (A : Type) := { do_index : t_Slice A -> R -> t_Slice A }.

#[global] Instance Indexable_Range {A : Type} `{t_Sized A} : Indexable (t_Range t_usize) A :=
  { do_index := fun s r =>
    let start := N.to_nat (U64_f_v (usize_0 (Range_f_start r))) in
    let stop := N.to_nat (U64_f_v (usize_0 (Range_f_end r))) in
    Build_t_Slice A (List.firstn (stop - start) (List.skipn start (Slice_f_v s))) }.

#[global] Instance Indexable_RangeTo {A : Type} `{t_Sized A} : Indexable (t_RangeTo t_usize) A :=
  { do_index := fun s r =>
    let stop := N.to_nat (U64_f_v (usize_0 (RangeTo_f_end r))) in
    Build_t_Slice A (List.firstn stop (Slice_f_v s)) }.

#[global] Instance Indexable_RangeFrom {A : Type} `{t_Sized A} : Indexable (t_RangeFrom t_usize) A :=
  { do_index := fun s r =>
    let start := N.to_nat (U64_f_v (usize_0 (RangeFrom_f_start r))) in
    Build_t_Slice A (List.skipn start (Slice_f_v s)) }.

(* ===== Indexing with Ranges (uses Indexable typeclass) ===== *)
Definition f_index {R A : Type} `{Indexable R A} (s : t_Slice A) (r : R) : t_Slice A :=
  do_index s r.
