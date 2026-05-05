module AbstractCrypto

(** Abstract Cryptographic Primitives for Signal Protocol Verification (Aeneas F*)

    This module provides abstract models of cryptographic operations used in
    the Signal Protocol, adapted for the Aeneas extraction style.

    Aeneas extracts Rust into a pure functional representation, so the types
    and conventions here match Aeneas-generated F* code rather than hax-generated
    F* code.
*)

#set-options "--fuel 0 --ifuel 1 --z3rlimit 40"

open FStar.Mul
open FStar.Seq

(** === Type Abbreviations === *)

type bytes = seq u8

type private_key = b:bytes { Seq.length b = 32 }

type public_key = b:bytes { Seq.length b = 32 }

type signature = b:bytes { Seq.length b = 64 }

type shared_secret = b:bytes { Seq.length b = 32 }

(** === Validation Functions === *)

let is_valid_private_key (b: bytes) : bool = Seq.length b = 32

let is_valid_public_key (b: bytes) : bool = Seq.length b = 32

let is_valid_signature (b: bytes) : bool = Seq.length b = 64

(** === Cryptographic Operations (Assumed/Abstract) === *)

assume val generate_private_key : unit -> Tot private_key

assume val public_key_of_private : private_key -> Tot public_key

assume val dh : private_key -> public_key -> Tot shared_secret

assume val sign : private_key -> bytes -> Tot signature

assume val verify : public_key -> signature -> bytes -> Tot bool

assume val hkdf_derive : salt:bytes -> ikm:bytes -> info:bytes -> len:nat
                        -> Tot (result bytes string)

assume val aead_encrypt : key:bytes -> plaintext:bytes -> aad:bytes -> nonce:bytes
                        -> Tot (result bytes string)

assume val aead_decrypt : key:bytes -> ciphertext:bytes -> aad:bytes -> nonce:bytes
                        -> Tot (result bytes string)

(** === Key Generation Guarantees === *)

assume val generate_private_key_valid: u:unit -> Lemma
  (ensures (is_valid_private_key (generate_private_key u)))

assume val public_key_of_private_valid: sk:private_key -> Lemma
  (requires (is_valid_private_key sk))
  (ensures (is_valid_public_key (public_key_of_private sk)))

(** === DH Security Axioms === *)

assume val dh_commutativity: sk1:private_key -> sk2:private_key -> Lemma
  (requires (is_valid_private_key sk1 /\ is_valid_private_key sk2))
  (ensures (dh sk1 (public_key_of_private sk2) = dh sk2 (public_key_of_private sk1)))

assume val dh_deterministic: sk:private_key -> pk:public_key -> Lemma
  (ensures (dh sk pk = dh sk pk))

assume val dh_produces_shared_secret: sk:private_key -> pk:public_key -> Lemma
  (requires (is_valid_private_key sk /\ is_valid_public_key pk))
  (ensures (Seq.length (dh sk pk) = 32))

(** === Signature Security Axioms === *)

assume val sign_verify_correct: sk:private_key -> data:bytes -> Lemma
  (requires (is_valid_private_key sk))
  (ensures (verify (public_key_of_private sk) (sign sk data) data = true))

assume val sign_produces_signature: sk:private_key -> data:bytes -> Lemma
  (requires (is_valid_private_key sk))
  (ensures (is_valid_signature (sign sk data)))

assume val verify_rejects_wrong_key: sk1:private_key -> sk2:private_key -> data:bytes -> Lemma
  (requires (is_valid_private_key sk1 /\ is_valid_private_key sk2 /\ sk1 <> sk2))
  (ensures (verify (public_key_of_private sk1) (sign sk2 data) data = false))

(** === Key Indistinguishability Axioms === *)

assume val key_injection: sk1:private_key -> sk2:private_key -> Lemma
  (requires (is_valid_private_key sk1 /\ is_valid_private_key sk2 /\ sk1 <> sk2))
  (ensures (public_key_of_private sk1 <> public_key_of_private sk2))

assume val key_injection_inverse: sk1:private_key -> sk2:private_key -> Lemma
  (requires (is_valid_private_key sk1 /\ is_valid_private_key sk2 /\
             public_key_of_private sk1 = public_key_of_private sk2))
  (ensures (sk1 = sk2))

(** === Forward Secrecy Axioms === *)

assume val forward_secrecy_dh: identity_sk:private_key -> ephemeral_sk:private_key -> pk:public_key -> Lemma
  (requires (is_valid_private_key identity_sk /\
             is_valid_private_key ephemeral_sk /\
             is_valid_public_key pk /\
             identity_sk <> ephemeral_sk))
  (ensures (dh ephemeral_sk pk <> dh identity_sk pk))

(** === HKDF Security Axioms === *)

assume val hkdf_output_length: salt:bytes -> ikm:bytes -> info:bytes -> len:nat -> Lemma
  (ensures (match hkdf_derive salt ikm info len with
            | Ok output -> True
            | Err _ -> True))

assume val hkdf_deterministic: salt:bytes -> ikm:bytes -> info:bytes -> len:nat -> Lemma
  (ensures (hkdf_derive salt ikm info len = hkdf_derive salt ikm info len))

(** === AEAD Security Axioms === *)

assume val aead_round_trip: key:bytes -> plaintext:bytes -> aad:bytes -> nonce:bytes -> Lemma
  (ensures (match aead_encrypt key plaintext aad nonce with
            | Ok ciphertext ->
                aead_decrypt key ciphertext aad nonce = Ok plaintext
            | Err _ -> True))

(** === X3DH Key Agreement Axioms === *)

assume val x3dh_key_agreement: alice_ik_sk:private_key -> alice_ek_sk:private_key ->
                               bob_ik_sk:private_key -> bob_spk_sk:private_key -> Lemma
  (requires (is_valid_private_key alice_ik_sk /\
             is_valid_private_key alice_ek_sk /\
             is_valid_private_key bob_ik_sk /\
             is_valid_private_key bob_spk_sk))
  (ensures (let alice_ik_pk = public_key_of_private alice_ik_sk in
            let alice_ek_pk = public_key_of_private alice_ek_sk in
            let bob_ik_pk = public_key_of_private bob_ik_sk in
            let bob_spk_pk = public_key_of_private bob_spk_sk in
            dh alice_ik_sk bob_spk_pk = dh bob_spk_sk alice_ik_pk /\
            dh alice_ek_sk bob_ik_pk = dh bob_ik_sk alice_ek_pk /\
            dh alice_ek_sk bob_spk_pk = dh bob_spk_sk alice_ek_pk))

assume val x3dh_key_agreement_with_opk: alice_ek_sk:private_key -> bob_opk_sk:private_key -> Lemma
  (requires (is_valid_private_key alice_ek_sk /\ is_valid_private_key bob_opk_sk))
  (ensures (let alice_ephemeral_pk = public_key_of_private alice_ek_sk in
            let bob_opk_pk = public_key_of_private bob_opk_sk in
            dh alice_ek_sk bob_opk_pk = dh bob_opk_sk alice_ephemeral_pk))

(** === Utility Functions === *)

assume val empty_bytes : bytes

assume val concat_bytes : a:bytes -> b:bytes -> Tot bytes

assume val zero_bytes : len:nat -> bytes

assume val slice_bytes : b:bytes -> start:nat -> len:nat{start + len <= Seq.length b} -> bytes
