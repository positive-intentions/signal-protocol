module Spec.X3DH

(** Spec.X3DH: the Extended Triple Diffie-Hellman key-agreement protocol
    from the Signal X3DH specification, version 1.0
    (https://signal.org/docs/specifications/x3dh/, June 2016).

    This module defines the X3DH key schedule independently of any Rust
    implementation, and proves that initiator and responder agree on the
    shared secret SK (lemma [agreement] below) using only
    [Spec.Crypto.dh_commutativity]. The Rust implementation in
    [signal-protocol-core/src/x3dh.rs] is later shown (via hax extraction
    + refinement) to compute exactly this key schedule. *)

#set-options "--fuel 0 --ifuel 1 --z3rlimit 30"

open FStar.Seq
open Spec.Crypto

(** === Whitepaper constants === *)

(** [F = 0xFF^32] - the constant prefix required by X3DH §3.3 step 3.
    Its purpose is to domain-separate the KDF input from a plain DH-output
    stream (so an attacker who knows just [DH1 || ... || DH4] cannot mount
    chosen-ciphertext-style attacks against the KDF). *)
val f_prefix : lbytes 32
let f_prefix = Seq.create 32 0xFFuy

(** Salt and info strings used by the X3DH HKDF call. The byte sequences
    must equal the constants in [signal-protocol-core/src/x3dh.rs]:
    - salt = "Signal_X3DH_Salt"
    - info = "Signal_X3DH_Key_Derivation"
    For the spec we treat them as opaque byte sequences; the Rust
    refinement proof discharges the equality. *)
assume val salt_x3dh : bytes
assume val info_x3dh : bytes

(** === Public bundles exchanged between Alice and Bob === *)

noeq type bob_bundle = {
  ik:      public_key;        (** Bob's identity key.            *)
  spk:     public_key;        (** Bob's signed prekey.           *)
  spk_sig: signature;         (** Bob's Ed25519 signature on spk
                                  under his identity key.        *)
  opk:     option public_key; (** Optional one-time prekey.      *)
}

noeq type alice_bundle = {
  ik: public_key;             (** Alice's identity key.    *)
  ek: public_key;             (** Alice's ephemeral key.   *)
}

(** === Private state === *)

noeq type alice_state = {
  ik_sk: private_key;
  ek_sk: private_key;
}

noeq type bob_state = {
  ik_sk:  private_key;
  spk_sk: private_key;
  opk_sk: option private_key;
}

(** === KDF input construction === *)

(** Concatenation of the (three or four) DH outputs in the order
    DH1 || DH2 || DH3 [|| DH4] mandated by X3DH §3.3 step 4. *)
let dh_concat
    (dh1 dh2 dh3: shared_secret)
    (dh4_opt: option shared_secret)
  : Tot bytes
=
  let base = Seq.append (Seq.append dh1 dh2) dh3 in
  match dh4_opt with
  | None     -> base
  | Some dh4 -> Seq.append base dh4

(** Full KDF input: [F || DH1 || DH2 || DH3 [|| DH4]]. *)
let kdf_input
    (dh1 dh2 dh3: shared_secret)
    (dh4_opt: option shared_secret)
  : Tot bytes
=
  Seq.append f_prefix (dh_concat dh1 dh2 dh3 dh4_opt)

(** === The X3DH key schedule === *)

(** Initiator (Alice) computes SK from her private state and Bob's bundle.

    Per X3DH §3.3:
      DH1 = DH(IK_a, SPK_b)
      DH2 = DH(EK_a, IK_b)
      DH3 = DH(EK_a, SPK_b)
      DH4 = DH(EK_a, OPK_b)   (optional)
      SK  = HKDF(salt, F || DH1 || DH2 || DH3 [|| DH4], info, 32) *)
val sk_initiator : alice_state -> bob_bundle -> Tot shared_secret
let sk_initiator a b =
  let dh1 = dh a.ik_sk b.spk in
  let dh2 = dh a.ek_sk b.ik in
  let dh3 = dh a.ek_sk b.spk in
  let dh4_opt =
    match b.opk with
    | None        -> None
    | Some opk_pk -> Some (dh a.ek_sk opk_pk)
  in
  hkdf salt_x3dh (kdf_input dh1 dh2 dh3 dh4_opt) info_x3dh shared_secret_len

(** Responder (Bob) computes SK from his private state and Alice's bundle.
    The DH operations are inverted (Bob uses his private keys with Alice's
    public keys); their results equal Alice's by [dh_commutativity]. *)
val sk_responder : bob_state -> alice_bundle -> Tot shared_secret
let sk_responder b a =
  let dh1 = dh b.spk_sk a.ik in
  let dh2 = dh b.ik_sk  a.ek in
  let dh3 = dh b.spk_sk a.ek in
  let dh4_opt =
    match b.opk_sk with
    | None        -> None
    | Some opk_sk -> Some (dh opk_sk a.ek)
  in
  hkdf salt_x3dh (kdf_input dh1 dh2 dh3 dh4_opt) info_x3dh shared_secret_len

(** === Bundle construction === *)

(** Bundles Alice and Bob would build from their states (i.e., the
    public-side projection of their secrets). *)
let alice_bundle_of (a: alice_state) : Tot alice_bundle = {
  ik = public_key_of_private a.ik_sk;
  ek = public_key_of_private a.ek_sk;
}

let bob_bundle_of (b: bob_state) : Tot bob_bundle = {
  ik      = public_key_of_private b.ik_sk;
  spk     = public_key_of_private b.spk_sk;
  spk_sig = sign b.ik_sk (public_key_of_private b.spk_sk);
  opk     = (match b.opk_sk with
             | None    -> None
             | Some sk -> Some (public_key_of_private sk));
}

(** === Theorem: initiator and responder agree on SK === *)

(** When the bundles Alice and Bob exchange are the public projections of
    their respective states, [sk_initiator] and [sk_responder] yield the
    same shared secret. The proof uses [dh_commutativity] on each of the
    (three or four) DH operations; F* discharges the structural equality
    on the [hkdf] / [kdf_input] / [dh_concat] expressions automatically. *)
val agreement : a: alice_state -> b: bob_state ->
  Lemma
    (ensures
      sk_initiator a (bob_bundle_of b) ==
      sk_responder b (alice_bundle_of a))

let agreement a b =
  dh_commutativity a.ik_sk b.spk_sk;
  dh_commutativity a.ek_sk b.ik_sk;
  dh_commutativity a.ek_sk b.spk_sk;
  match b.opk_sk with
  | None        -> ()
  | Some opk_sk -> dh_commutativity a.ek_sk opk_sk

(** === Signed-prekey signature check (Alice's responsibility) === *)

(** Alice MUST verify Bob's signed-prekey signature before deriving SK
    (X3DH §3.3 step 1). This predicate captures that check. *)
let valid_bob_bundle (b: bob_bundle) : Tot bool =
  verify b.ik b.spk_sig b.spk

(** When Bob's bundle is built honestly, the signature is valid. *)
val bob_bundle_of_valid : b: bob_state ->
  Lemma (ensures valid_bob_bundle (bob_bundle_of b) == true)
let bob_bundle_of_valid b =
  sign_verify_correct b.ik_sk (public_key_of_private b.spk_sk)

(** === Safe initiator entry point ===

    [sk_initiator] above does not verify Bob's signed-prekey signature.
    The whitepaper §3.3 step 1 mandates that verification, and the
    ProVerif `signal_complete.pv` model relies on it for the secrecy
    proof to go through. The safe entry point [sk_initiator_safe] is
    a partial function that returns [None] if the signature does not
    verify and the X3DH-output [shared_secret] otherwise. The Rust
    implementation [`signal_protocol_core::x3dh_initiate`] refines this. *)
val sk_initiator_safe : alice_state -> bob_bundle -> Tot (option shared_secret)
let sk_initiator_safe a b =
  if valid_bob_bundle b
  then Some (sk_initiator a b)
  else None

(** Theorem: when Bob constructs his bundle honestly from his state,
    the safe initiator and the responder agree on SK. The proof
    composes [bob_bundle_of_valid] with [agreement]. *)
val agreement_safe : a: alice_state -> b: bob_state ->
  Lemma
    (ensures (
      let bb = bob_bundle_of b in
      sk_initiator_safe a bb == Some (sk_responder b (alice_bundle_of a))))
let agreement_safe a b =
  bob_bundle_of_valid b;
  agreement a b
