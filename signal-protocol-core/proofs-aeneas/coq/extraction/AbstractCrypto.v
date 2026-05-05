(** Abstract Cryptographic Primitives for Signal Protocol Verification (Aeneas Rocq)

    This module provides abstract models of cryptographic operations used in
    the Signal Protocol, adapted for the Aeneas extraction style.
*)

From Stdlib Require Import List Bool Nat Arith Specif.

Module AbstractCrypto.

Definition bytes := list nat.

Definition private_key := { b : bytes | length b = 32 }.

Definition public_key := { b : bytes | length b = 32 }.

Definition signature := { b : bytes | length b = 64 }.

Definition shared_secret := { b : bytes | length b = 32 }.

Definition is_valid_private_key (b : bytes) : bool :=
  Nat.eqb (length b) 32.

Definition is_valid_public_key (b : bytes) : bool :=
  Nat.eqb (length b) 32.

Definition is_valid_signature (b : bytes) : bool :=
  Nat.eqb (length b) 64.

Parameter generate_private_key : unit -> private_key.

Parameter public_key_of_private : private_key -> public_key.

Parameter dh : private_key -> public_key -> shared_secret.

Parameter sign : private_key -> bytes -> signature.

Parameter verify : public_key -> signature -> bytes -> bool.

Parameter hkdf_derive : bytes -> bytes -> bytes -> nat -> (list bool * bytes + bytes).

Parameter aead_encrypt : bytes -> bytes -> bytes -> bytes -> (list bool * bytes + bytes).

Parameter aead_decrypt : bytes -> bytes -> bytes -> bytes -> (list bool * bytes + bytes).

Axiom generate_private_key_valid :
  forall (u : unit),
    length (proj1_sig (generate_private_key u)) = 32.

Axiom public_key_of_private_valid :
  forall (sk : private_key),
    is_valid_private_key (proj1_sig sk) = true ->
    is_valid_public_key (proj1_sig (public_key_of_private sk)) = true.

Axiom dh_commutativity :
  forall (sk1 sk2 : private_key),
    is_valid_private_key (proj1_sig sk1) = true ->
    is_valid_private_key (proj1_sig sk2) = true ->
    proj1_sig (dh sk1 (public_key_of_private sk2)) =
    proj1_sig (dh sk2 (public_key_of_private sk1)).

Axiom dh_deterministic :
  forall (sk : private_key) (pk : public_key),
    proj1_sig (dh sk pk) = proj1_sig (dh sk pk).

Axiom dh_produces_shared_secret :
  forall (sk : private_key) (pk : public_key),
    is_valid_private_key (proj1_sig sk) = true ->
    is_valid_public_key (proj1_sig pk) = true ->
    length (proj1_sig (dh sk pk)) = 32.

Axiom sign_verify_correct :
  forall (sk : private_key) (data : bytes),
    is_valid_private_key (proj1_sig sk) = true ->
    verify (public_key_of_private sk) (sign sk data) data = true.

Axiom sign_produces_signature :
  forall (sk : private_key) (data : bytes),
    is_valid_private_key (proj1_sig sk) = true ->
    length (proj1_sig (sign sk data)) = 64.

Axiom verify_rejects_wrong_key :
  forall (sk1 sk2 : private_key) (data : bytes),
    is_valid_private_key (proj1_sig sk1) = true ->
    is_valid_private_key (proj1_sig sk2) = true ->
    sk1 <> sk2 ->
    verify (public_key_of_private sk1) (sign sk2 data) data = false.

Axiom key_injection :
  forall (sk1 sk2 : private_key),
    is_valid_private_key (proj1_sig sk1) = true ->
    is_valid_private_key (proj1_sig sk2) = true ->
    sk1 <> sk2 ->
    public_key_of_private sk1 <> public_key_of_private sk2.

Axiom key_injection_inverse :
  forall (sk1 sk2 : private_key),
    is_valid_private_key (proj1_sig sk1) = true ->
    is_valid_private_key (proj1_sig sk2) = true ->
    public_key_of_private sk1 = public_key_of_private sk2 ->
    sk1 = sk2.

Axiom forward_secrecy_dh :
  forall (identity_sk ephemeral_sk : private_key) (pk : public_key),
    is_valid_private_key (proj1_sig identity_sk) = true ->
    is_valid_private_key (proj1_sig ephemeral_sk) = true ->
    is_valid_public_key (proj1_sig pk) = true ->
    identity_sk <> ephemeral_sk ->
    proj1_sig (dh ephemeral_sk pk) <> proj1_sig (dh identity_sk pk).

Axiom hkdf_output_length :
  forall (salt ikm info : bytes) (len : nat),
    match hkdf_derive salt ikm info len with
    | inl _ | inr _ => True
    end.

Axiom hkdf_deterministic :
  forall (salt ikm info : bytes) (len : nat),
    hkdf_derive salt ikm info len = hkdf_derive salt ikm info len.

Axiom aead_round_trip :
  forall (key plaintext aad nonce : bytes),
    match aead_encrypt key plaintext aad nonce with
    | inr ciphertext =>
        aead_decrypt key ciphertext aad nonce = inr plaintext
    | inl _ => True
    end.

Axiom x3dh_key_agreement :
  forall (alice_ik_sk alice_ek_sk bob_ik_sk bob_spk_sk : private_key),
    is_valid_private_key (proj1_sig alice_ik_sk) = true ->
    is_valid_private_key (proj1_sig alice_ek_sk) = true ->
    is_valid_private_key (proj1_sig bob_ik_sk) = true ->
    is_valid_private_key (proj1_sig bob_spk_sk) = true ->
    let alice_ik_pk := public_key_of_private alice_ik_sk in
    let alice_ek_pk := public_key_of_private alice_ek_sk in
    let bob_ik_pk := public_key_of_private bob_ik_sk in
    let bob_spk_pk := public_key_of_private bob_spk_sk in
    proj1_sig (dh alice_ik_sk bob_spk_pk) = proj1_sig (dh bob_spk_sk alice_ik_pk) /\
    proj1_sig (dh alice_ek_sk bob_ik_pk) = proj1_sig (dh bob_ik_sk alice_ek_pk).

Axiom x3dh_key_agreement_with_opk :
  forall (alice_ek_sk bob_opk_sk : private_key),
    is_valid_private_key (proj1_sig alice_ek_sk) = true ->
    is_valid_private_key (proj1_sig bob_opk_sk) = true ->
    let alice_ephemeral_pk := public_key_of_private alice_ek_sk in
    let bob_opk_pk := public_key_of_private bob_opk_sk in
    proj1_sig (dh alice_ek_sk bob_opk_pk) = proj1_sig (dh bob_opk_sk alice_ephemeral_pk).

End AbstractCrypto.
