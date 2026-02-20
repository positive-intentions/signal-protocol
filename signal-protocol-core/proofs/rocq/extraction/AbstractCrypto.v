module AbstractCrypto.

(** Abstract Cryptographic Primitives for Signal Protocol Verification *)

Require Import List.
Require Import Bool.
Require Import Nat.
Require Import Arith.
Require Import Omega.

(** === Type Definitions === *)

(** Byte sequences as lists of bytes *)
Definition bytes := list nat.

(** Private keys are 32-byte sequences *)
Definition private_key := b : bytes * length b = 32.

(** Public keys are 32-byte sequences *)
Definition public_key := b : bytes * length b = 32.

(** Signatures are 64-byte sequences *)
Definition signature := b : bytes * length b = 64.

(** Shared secrets from DH are 32 bytes *)
Definition shared_secret := b : bytes * length b = 32.

(** === Validation Functions === *)

Definition is_valid_private_key (b : bytes) : bool :=
  Nat.eqb (length b) 32.

Definition is_valid_public_key (b : bytes) : bool :=
  Nat.eqb (length b) 32.

Definition is_valid_signature (b : bytes) : bool :=
  Nat.eqb (length b) 64.

(** === Cryptographic Operations (Axioms) === *)

Parameter generate_private_key : unit -> unit * bytes.

Parameter public_key_of_private : private_key -> public_key.

Parameter dh : private_key -> public_key -> shared_secret.

Parameter sign : private_key -> bytes -> signature.

Parameter verify : public_key -> signature -> bytes -> bool.

Parameter hkdf_derive : bytes -> bytes -> bytes -> nat -> (list bool * bytes + bytes).

Parameter aead_encrypt : bytes -> bytes -> bytes -> bytes -> (list bool * bytes + bytes).

Parameter aead_decrypt : bytes -> bytes -> bytes -> bytes -> (list bool * bytes + bytes).

(** === Key Generation Guarantees === *)

Axiom generate_private_key_valid :
  forall (u : unit),
    length (snd (generate_private_key u)) = 32.

Axiom public_key_of_private_valid :
  forall (sk : private_key),
    is_valid_private_key (fst sk) = true ->
    is_valid_public_key (fst (public_key_of_private sk)) = true.

(** === DH Security Axioms === *)

Axiom dh_commutativity :
  forall (sk1 sk2 : private_key),
    is_valid_private_key (fst sk1) = true ->
    is_valid_private_key (fst sk2) = true ->
    fst (dh sk1 (public_key_of_private sk2)) =
    fst (dh sk2 (public_key_of_private sk1)).

Axiom dh_deterministic :
  forall (sk : private_key) (pk : public_key),
    fst (dh sk pk) = fst (dh sk pk).

Axiom dh_produces_shared_secret :
  forall (sk : private_key) (pk : public_key),
    is_valid_private_key (fst sk) = true ->
    is_valid_public_key (fst pk) = true ->
    length (fst (dh sk pk)) = 32.

(** === Signature Security Axioms === *)

Axiom sign_verify_correct :
  forall (sk : private_key) (data : bytes),
    is_valid_private_key (fst sk) = true ->
    verify (public_key_of_private sk) (sign sk data) data = true.

Axiom sign_produces_signature :
  forall (sk : private_key) (data : bytes),
    is_valid_private_key (fst sk) = true ->
    length (fst (sign sk data)) = 64.

Axiom verify_rejects_wrong_key :
  forall (sk1 sk2 : private_key) (data : bytes),
    is_valid_private_key (fst sk1) = true ->
    is_valid_private_key (fst sk2) = true ->
    sk1 <> sk2 ->
    verify (public_key_of_private sk1) (sign sk2 data) data = false.

(** === Key Indistinguishability Axioms === *)

Axiom key_injection :
  forall (sk1 sk2 : private_key),
    is_valid_private_key (fst sk1) = true ->
    is_valid_private_key (fst sk2) = true ->
    sk1 <> sk2 ->
    public_key_of_private sk1 <> public_key_of_private sk2.

Axiom key_injection_inverse :
  forall (sk1 sk2 : private_key),
    is_valid_private_key (fst sk1) = true ->
    is_valid_private_key (fst sk2) = true ->
    public_key_of_private sk1 = public_key_of_private sk2 ->
    sk1 = sk2.

(** === Forward Secrecy Axioms === *)

Axiom forward_secrecy_dh :
  forall (identity_sk ephemeral_sk : private_key) (pk : public_key),
    is_valid_private_key (fst identity_sk) = true ->
    is_valid_private_key (fst ephemeral_sk) = true ->
    is_valid_public_key (fst pk) = true ->
    identity_sk <> ephemeral_sk ->
    fst (dh ephemeral_sk pk) <> fst (dh identity_sk pk).

(** === HKDF Security Axioms === *)

Axiom hkdf_output_length :
  forall (salt ikm info : bytes) (len : nat),
    match hkdf_derive salt ikm info len with
    | inl _ | inr _ => True
    end.

Axiom hkdf_deterministic :
  forall (salt ikm info : bytes) (len : nat),
    hkdf_derive salt ikm info len = hkdf_derive salt ikm info len.

(** === AEAD Security Axioms === *)

Axiom aead_round_trip :
  forall (key plaintext aad nonce : bytes),
    match aead_encrypt key plaintext aad nonce with
    | inr ciphertext =>
        aead_decrypt key ciphertext aad nonce = inr plaintext
    | inl _ => True
    end.

(** === X3DH Key Agreement Axioms === *)

Axiom x3dh_key_agreement :
  forall (alice_ik_sk alice_ek_sk bob_ik_sk bob_spk_sk : private_key),
    is_valid_private_key (fst alice_ik_sk) = true ->
    is_valid_private_key (fst alice_ek_sk) = true ->
    is_valid_private_key (fst bob_ik_sk) = true ->
    is_valid_private_key (fst bob_spk_sk) = true ->
    let alice_ik_pk := public_key_of_private alice_ik_sk in
    let alice_ek_pk := public_key_of_private alice_ek_sk in
    let bob_ik_pk := public_key_of_private bob_ik_sk in
    let bob_spk_pk := public_key_of_private bob_spk_sk in
    fst (dh alice_ik_sk bob_spk_pk) = fst (dh bob_spk_pk alice_ik_pk) /\
    fst (dh alice_ek_sk bob_ik_pk) = fst (dh bob_ik_sk alice_ek_pk).

Axiom x3dh_key_agreement_with_opk :
  forall (alice_ek_sk bob_opk_sk : private_key),
    is_valid_private_key (fst alice_ek_sk) = true ->
    is_valid_private_key (fst bob_opk_sk) = true ->
    let alice_ephemeral_pk := public_key_of_private alice_ek_sk in
    let bob_opk_pk := public_key_of_private bob_opk_sk in
    fst (dh alice_ek_sk bob_opk_pk) = fst (dh bob_opk_sk alice_ephemeral_pk).

End AbstractCrypto.