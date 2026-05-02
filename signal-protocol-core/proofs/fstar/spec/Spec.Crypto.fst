module Spec.Crypto

(** Spec.Crypto: Cryptographic primitives for the Signal Protocol spec.

    This module defines the *abstract interface* of the cryptographic
    primitives used by the Signal Protocol (X3DH, Double Ratchet) and
    states only the *minimal* security assumptions that the protocol-level
    proofs depend on.

    What we assume:

    - [dh_commutativity] - the only DH equation X3DH and the DH ratchet rely on.
    - [sign_verify_correct] - functional correctness of Ed25519.
    - [aead_correctness]   - functional round-trip of AES-256-GCM.

    What we DO NOT assume (because it is either tautological or strictly
    stronger than what we need):

    - [dh sk pk = dh sk pk]   - automatic from [Tot].
    - [length (dh sk pk) = 32] - encoded in the return type.
    - "different keys give different DH outputs" - that is not forward
      secrecy; forward secrecy is an indistinguishability property and
      lives in [Spec.Security.Games].
    - "x3dh produces matching secrets" - this is a *theorem* of the X3DH
      spec, proved in [Spec.X3DH] from [dh_commutativity] alone.

    Higher-level cryptographic security (DDH, EUF-CMA, IND-CCA, PRF) is
    captured in [Spec.Security.Games]. Those games reduce protocol
    properties to standard hardness assumptions but are not on the
    extraction critical path. *)

#set-options "--fuel 0 --ifuel 1 --z3rlimit 30"

open FStar.Seq
open Rust_primitives.Integers

(** === Byte sequences === *)

(** [bytes] is interchangeable with [Rust_primitives.Arrays.t_Slice u8]
    and with the unrefined [Seq.seq u8] used throughout the hax F* proof
    libraries. Length is bounded by [max_usize] so it embeds into Rust. *)
type bytes = b: Seq.seq UInt8.t { Seq.length b <= max_usize }

(** Length-refined byte sequences. *)
type lbytes (n: nat { n <= max_usize }) = b: bytes { Seq.length b == n }

(** === Key, signature, and shared-secret sizes === *)

let private_key_len   : n: nat { n <= max_usize } = 32
let public_key_len    : n: nat { n <= max_usize } = 32
let signature_len     : n: nat { n <= max_usize } = 64
let shared_secret_len : n: nat { n <= max_usize } = 32
let aead_key_len      : n: nat { n <= max_usize } = 32
let nonce_len         : n: nat { n <= max_usize } = 12
let aead_tag_len      : n: nat { n <= max_usize } = 16
let hmac_output_len   : n: nat { n <= max_usize } = 32

type private_key   = lbytes private_key_len
type public_key    = lbytes public_key_len
type signature     = lbytes signature_len
type shared_secret = lbytes shared_secret_len
type aead_key      = lbytes aead_key_len
type nonce         = lbytes nonce_len

(** === Key derivation === *)

(** Derive a public key from a private key. [Tot] makes it deterministic. *)
assume val public_key_of_private : private_key -> Tot public_key

(** Generate a fresh private key. Modeled as a [Tot] function for spec
    purposes; a real cryptographic analysis treats this as a uniform
    sample from {0,1}^256 and threads coin flips through a state monad.
    The protocol-level proofs in [Spec.X3DH] / [Spec.DoubleRatchet] do
    not depend on this distinction. *)
assume val generate_private_key : unit -> Tot private_key

(** === Diffie-Hellman === *)

(** X25519 Diffie-Hellman. Result is a 32-byte shared secret. *)
assume val dh : private_key -> public_key -> Tot shared_secret

(** The only DH equation used in the protocol-level proofs. *)
assume
val dh_commutativity (sk1 sk2: private_key) :
  Lemma
    (ensures
      dh sk1 (public_key_of_private sk2) ==
      dh sk2 (public_key_of_private sk1))

(** === Ed25519 signatures === *)

assume val sign   : private_key -> bytes -> Tot signature
assume val verify : public_key -> signature -> bytes -> Tot bool

(** Functional correctness of signing under the matching public key. *)
assume
val sign_verify_correct (sk: private_key) (data: bytes) :
  Lemma (ensures verify (public_key_of_private sk) (sign sk data) data == true)

(** === HKDF (HMAC-SHA-256 based) === *)

(** HKDF as a deterministic [Tot] function whose output length equals the
    requested length. No separate length axiom is needed: it is encoded
    in the return type. *)
assume val hkdf : salt:bytes -> ikm:bytes -> info:bytes -> len:(n:nat{n <= max_usize}) -> Tot (lbytes len)

(** === HMAC-SHA-256 (used by the Double Ratchet symmetric KDF) === *)

assume val hmac_sha256 : key:lbytes 32 -> data:bytes -> Tot (lbytes hmac_output_len)

(** === AEAD (AES-256-GCM) === *)

(** Encryption returns ciphertext bytes; the GCM authentication tag is
    appended, so output length = plaintext length + tag length. *)
assume
val aead_encrypt
  (key: aead_key) (plaintext: bytes) (aad: bytes) (n: nonce) :
  Tot (c: bytes { Seq.length c == Seq.length plaintext + aead_tag_len })

(** Decryption is partial: returns [None] on tag failure. *)
assume
val aead_decrypt
  (key: aead_key) (ciphertext: bytes) (aad: bytes) (n: nonce) :
  Tot (option bytes)

(** Functional round-trip: a faithful (key, nonce, aad) triple recovers
    the plaintext. This is the *only* AEAD assumption used by the
    refinement proofs; IND-CCA security is in [Spec.Security.Games]. *)
assume
val aead_correctness
  (key: aead_key) (plaintext: bytes) (aad: bytes) (n: nonce) :
  Lemma
    (ensures
      aead_decrypt key (aead_encrypt key plaintext aad n) aad n ==
      Some plaintext)
