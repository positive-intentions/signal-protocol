module Test_syntax
#set-options "--fuel 0 --ifuel 1 --z3rlimit 40"

assume val test_axiom: unit -> Tot bool
