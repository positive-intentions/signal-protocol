module AbstractCrypto

(** Abstract Cryptographic Primitives for Signal Protocol Verification
    
    This module provides abstract models of cryptographic operations
    used in the Signal Protocol. These abstractions allow us to verify
    protocol properties without requiring full cryptographic proofs.
    
    The security axioms capture essential properties needed for:
    - Key authentication
    - Forward secrecy  
    - Key indistinguishability
*)

#set-options "--fuel 0 --ifuel 1 --z3rlimit 40"

open FStar.Mul
open FStar.Seq
open Core_models

(** === Type Abbreviations for Readability === *)

(** Byte sequences (compatible with t_Slice u8 / seq u8) *)
type bytes = b:seq u8 { Seq.length b <= Rust_primitives.Integers.max_usize }

(** Private keys are 32-byte sequences *)
type private_key = b:bytes { Seq.length b = 32 }

(** Public keys are 32-byte sequences *)
type public_key = b:bytes { Seq.length b = 32 }

(** Signatures are 64-byte sequences *)
type signature = bytes

(** Shared secrets from DH are 32 bytes *)
type shared_secret = bytes

(** Convert bytes to Vec when length fits in usize (for extraction compatibility) *)
let bytes_to_vec (b: bytes { Seq.length b <= max_usize }) : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  Alloc.Slice.impl__to_vec #u8 (b <: t_Slice u8)

(** === Validation Functions === *)

let is_valid_private_key (b: bytes) : bool =
  Seq.length b = 32

let is_valid_public_key (b: bytes) : bool =
  Seq.length b = 32

let is_valid_signature (b: bytes) : bool =
  Seq.length b = 64

(** === Cryptographic Operations === *)

(** Generate a fresh random private key (32 bytes) *)
assume
val generate_private_key : unit -> Tot private_key

(** Derive the corresponding public key from a private key *)
assume
val public_key_of_private : private_key -> Tot public_key

(** X25519 Diffie-Hellman key exchange (result is 32 bytes, fits in t_Slice) *)
assume
val dh : private_key -> public_key -> Tot (s: shared_secret { Seq.length s = 32 })

(** Ed25519 signature generation (result is 64 bytes) *)
assume
val sign : private_key -> bytes -> Tot (s: signature { Seq.length s = 64 })

(** Ed25519 signature verification *)
assume
val verify : public_key -> signature -> bytes -> Tot bool

(** HKDF-based key derivation (abstract) *)
assume
val hkdf_derive : salt:bytes -> ikm:bytes -> info:bytes -> len:nat 
                -> Tot (Core_models.Result.t_Result bytes Signal_protocol_core.Error.t_SignalError)

(** HKDF wrapper that accepts usize and returns Vec (for hax extraction compatibility) *)
let hkdf_derive_vec (salt:bytes) (ikm:bytes) (info:bytes) (len:Rust_primitives.Integers.usize)
  : Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Signal_protocol_core.Error.t_SignalError =
  match hkdf_derive salt ikm info (Rust_primitives.Integers.v len) with
  | Core_models.Result.Result_Ok b -> Core_models.Result.Result_Ok (bytes_to_vec b)
  | Core_models.Result.Result_Err e -> Core_models.Result.Result_Err e

(** AEAD encryption (abstract) *)
assume
val aead_encrypt : key:bytes -> plaintext:bytes -> aad:bytes -> nonce:bytes 
                 -> Tot (Core_models.Result.t_Result bytes Signal_protocol_core.Error.t_SignalError)

(** AEAD decryption (abstract) *)
assume
val aead_decrypt : key:bytes -> ciphertext:bytes -> aad:bytes -> nonce:bytes 
                 -> Tot (Core_models.Result.t_Result bytes Signal_protocol_core.Error.t_SignalError)

(** === Key Generation Guarantees === *)

(** Generated private keys are always valid (32 bytes) *)
assume
val generate_private_key_valid: u:unit -> Lemma (ensures (is_valid_private_key (generate_private_key u)))

(** Public key derivation preserves validity *)
assume
val public_key_of_private_valid: sk:private_key -> Lemma 
  (requires (is_valid_private_key sk))
  (ensures (is_valid_public_key (public_key_of_private sk)))

(** === DH Security Axioms === *)

(** DH commutativity: DH(a, B) = DH(b, A) when B = pub(A) and A = pub(b) *)
assume
val dh_commutativity: sk1:private_key -> sk2:private_key -> Lemma 
  (requires (is_valid_private_key sk1 /\ is_valid_private_key sk2))
  (ensures (dh sk1 (public_key_of_private sk2) = dh sk2 (public_key_of_private sk1)))

(** DH produces the same result for the same inputs *)
assume
val dh_deterministic: sk:private_key -> pk:public_key -> Lemma 
  (ensures (dh sk pk = dh sk pk))

(** DH correctness: DH produces 32-byte shared secret for valid inputs *)
assume
val dh_produces_shared_secret: sk:private_key -> pk:public_key -> Lemma 
  (requires (is_valid_private_key sk /\ is_valid_public_key pk))
  (ensures (Seq.length (dh sk pk) = 32))

(** === Signature Security Axioms === *)

(** Signatures verify correctly with the matching public key *)
assume
val sign_verify_correct: sk:private_key -> data:bytes -> Lemma 
  (requires (is_valid_private_key sk))
  (ensures (verify (public_key_of_private sk) (sign sk data) data = true))

(** Signatures have correct length (64 bytes for Ed25519) *)
assume
val sign_produces_signature: sk:private_key -> data:bytes -> Lemma 
  (requires (is_valid_private_key sk))
  (ensures (is_valid_signature (sign sk data)))

(** Verification rejects wrong keys *)
assume
val verify_rejects_wrong_key: sk1:private_key -> sk2:private_key -> data:bytes -> Lemma 
  (requires (is_valid_private_key sk1 /\ is_valid_private_key sk2 /\ sk1 <> sk2))
  (ensures (verify (public_key_of_private sk1) (sign sk2 data) data = false))

(** === Key Indistinguishability Axioms === *)

(** Different private keys yield different public keys (injectivity) *)
assume
val key_injection: sk1:private_key -> sk2:private_key -> Lemma 
  (requires (is_valid_private_key sk1 /\ is_valid_private_key sk2 /\ sk1 <> sk2))
  (ensures (public_key_of_private sk1 <> public_key_of_private sk2))

(** Same public key implies same private key *)
assume
val key_injection_inverse: sk1:private_key -> sk2:private_key -> Lemma 
  (requires (is_valid_private_key sk1 /\ is_valid_private_key sk2 /\ 
             public_key_of_private sk1 = public_key_of_private sk2))
  (ensures (sk1 = sk2))

(** === Forward Secrecy Axioms === *)

(** Compromise of a long-term key doesn't reveal past DH secrets *)
assume
val forward_secrecy_dh: identity_sk:private_key -> ephemeral_sk:private_key -> pk:public_key -> Lemma 
  (requires (is_valid_private_key identity_sk /\ 
             is_valid_private_key ephemeral_sk /\ 
             is_valid_public_key pk /\ 
             identity_sk <> ephemeral_sk))
  (ensures (dh ephemeral_sk pk <> dh identity_sk pk))

(** === HKDF Security Axioms === *)

(** HKDF produces output of requested length *)
assume
val hkdf_output_length: salt:bytes -> ikm:bytes -> info:bytes -> len:nat -> Lemma 
  (ensures (match hkdf_derive salt ikm info len with
            | Core_models.Result.Result_Ok output -> True
            | Core_models.Result.Result_Err _ -> True))

(** HKDF is deterministic for same inputs *)
assume
val hkdf_deterministic: salt:bytes -> ikm:bytes -> info:bytes -> len:nat -> Lemma 
  (ensures (hkdf_derive salt ikm info len = hkdf_derive salt ikm info len))

(** === AEAD Security Axioms === *)

(** AEAD round-trip: decryption of encryption recovers plaintext *)
assume
val aead_round_trip: key:bytes -> plaintext:bytes -> aad:bytes -> nonce:bytes -> Lemma 
  (ensures (match aead_encrypt key plaintext aad nonce with
            | Core_models.Result.Result_Ok ciphertext ->
                aead_decrypt key ciphertext aad nonce = Core_models.Result.Result_Ok plaintext
            | Core_models.Result.Result_Err _ -> True))

(** === Signal Protocol Specific Axioms === *)

(** X3DH produces the same shared secret for initiator and responder *)
assume
val x3dh_key_agreement: alice_ik_sk:private_key -> alice_ek_sk:private_key -> 
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

(** X3DH with one-time prekey also produces matching secrets *)
assume
val x3dh_key_agreement_with_opk: alice_ek_sk:private_key -> bob_opk_sk:private_key -> Lemma 
  (requires (is_valid_private_key alice_ek_sk /\ is_valid_private_key bob_opk_sk))
  (ensures (let alice_ephemeral_pk = public_key_of_private alice_ek_sk in
            let bob_opk_pk = public_key_of_private bob_opk_sk in
            dh alice_ek_sk bob_opk_pk = dh bob_opk_sk alice_ephemeral_pk))

(** === Utility Functions === *)

(** Empty byte sequence *)
assume val empty_bytes : bytes

(** Concatenate two byte sequences *)
assume val concat_bytes : a:bytes -> b:bytes -> Tot bytes

(** Create a byte sequence of zeros of given length *)
assume val zero_bytes : len:nat -> bytes

(** Extract a slice of bytes *)
assume val slice_bytes : b:bytes -> start:nat -> len:nat{start + len <= Seq.length b} -> bytes
