module Spec.Security.Games.Auth

(** Spec.Security.Games.Auth: authentication game-based definitions.

    Captures EUF-CMA for Ed25519 and INT-CTXT (ciphertext integrity) for
    AES-256-GCM. As with [Spec.Security.Games.IndCpa], this is
    scaffolding off the extraction critical path.

    Authentication of the X3DH handshake follows from EUF-CMA on the
    signed-prekey signature plus key-binding properties of the DH
    output; the formal reductions are future work. *)

#set-options "--fuel 0 --ifuel 1 --z3rlimit 30"

open FStar.Seq
open Spec.Crypto

(** === EUF-CMA for Ed25519 === *)

(** An EUF-CMA adversary, given a public key and access to a signing
    oracle, cannot produce a valid signature on a fresh message. *)
assume val ed25519_euf_cma : prop

(** === INT-CTXT for AES-256-GCM === *)

(** Ciphertext integrity: an adversary cannot produce a fresh ciphertext
    that decrypts under an honest key (with chosen nonces and AAD). *)
assume val aead_int_ctxt : prop

(** === Combined AEAD strength === *)

(** AEAD security = IND-CPA + INT-CTXT (standard composition).
    Restated here for symmetry with the rest of the development. *)
assume val aead_secure : prop
