module Test_syntax
#set-options "--fuel 0 --ifuel 1 --z3rlimit 40"

open FStar.Seq

let is_valid (b: bytes) : bool = Seq.length b = 32

val gen_key : unit -> Tot bytes

assume val test_axiom: u:unit -> Lemma (ensures (is_valid (gen_key u)))
