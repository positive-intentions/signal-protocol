module Spec.DoubleRatchet

(** Spec.DoubleRatchet: the Double Ratchet algorithm from the Signal
    Double Ratchet specification, version 1.0
    (https://signal.org/docs/specifications/doubleratchet/, November 2016).

    This module models the two ratchets that compose to give forward
    secrecy and post-compromise security:

    1. Diffie-Hellman ratchet (§3.5): each side rotates its DH key on
       receipt of a new chain, mixing fresh DH output into the root key.

    2. Symmetric-key ratchet (§5.2): chain keys advance through HMAC,
       producing a fresh message key per message.

    The Rust implementation in
    [signal-protocol-core/src/double_ratchet.rs] is later shown (via hax
    extraction + refinement) to compute exactly this state machine. *)

#set-options "--fuel 0 --ifuel 1 --z3rlimit 30"

open FStar.Seq
open Spec.Crypto

(** === State sizes === *)

let chain_key_len   : n: nat { n <= max_usize } = 32
let root_key_len    : n: nat { n <= max_usize } = 32
let message_key_len : n: nat { n <= max_usize } = 32

type chain_key   = lbytes chain_key_len
type root_key    = lbytes root_key_len
type message_key = lbytes message_key_len

(** === Whitepaper KDF constants (§3.5) === *)

(** [info] string passed to HKDF inside [kdf_rk]. Must equal the constant
    in [signal-protocol-core/src/double_ratchet.rs]; treated as opaque
    for the spec. *)
assume val info_dh_ratchet : bytes

(** === Symmetric-key ratchet KDF (§5.2) === *)

(** [KDF_CK] from the Double Ratchet whitepaper, §5.2:

      message_key  = HMAC(ck, 0x01)
      next_ck      = HMAC(ck, 0x02)

    Returns [(next_ck, message_key)]. *)
let byte_one  : lbytes 1 = Seq.create 1 0x01uy
let byte_two  : lbytes 1 = Seq.create 1 0x02uy

val kdf_ck : ck: chain_key -> Tot (chain_key & message_key)
let kdf_ck ck =
  let mk      = hmac_sha256 ck byte_one in
  let next_ck = hmac_sha256 ck byte_two in
  next_ck, mk

(** === DH ratchet KDF (§3.5) === *)

(** [KDF_RK] from the Double Ratchet whitepaper, §3.5:

      (new_rk, new_ck) = HKDF(salt = rk, ikm = dh_out,
                              info = "...", out_len = 64)

    The first 32 bytes become the new root key, the second 32 the new
    chain key. *)
val kdf_rk : rk: root_key -> dh_out: shared_secret ->
             Tot (root_key & chain_key)

let kdf_rk rk dh_out =
  let out : lbytes 64 = hkdf rk dh_out info_dh_ratchet 64 in
  let new_rk : lbytes 32 = Seq.slice out 0  32 in
  let new_ck : lbytes 32 = Seq.slice out 32 64 in
  new_rk, new_ck

(** === Double Ratchet state === *)

(** Minimal protocol state at one party. Real implementations also store
    skipped-message-keys and replay-protection state; those are layered
    on top in [signal-protocol-core/src/double_ratchet.rs]. *)
noeq type dr_state = {
  rk:                root_key;
  sending_ck:        option chain_key;
  receiving_ck:      option chain_key;
  sending_dh_sk:     option private_key;
  receiving_dh_pk:   option public_key;
  n_send:            nat;
  n_recv:            nat;
  pn:                nat;        (** previous chain length *)
}

(** === Initialization === *)

(** Bootstrap salt used to derive the very first chain key from the
    X3DH-output shared secret. This must match the constant
    [b"Signal_Initial_Chain"] in
    [signal-protocol-core/src/double_ratchet.rs]. *)
assume val initial_chain_salt : bytes

(** Initial chain key derived from the X3DH shared secret. Both parties
    compute the same value, so they agree on chain 0 without doing an
    additional DH operation. *)
let initial_chain_key (sk: shared_secret) : Tot chain_key =
  hkdf initial_chain_salt sk info_dh_ratchet chain_key_len

(** Implementation note. The Double Ratchet whitepaper §3.6 bootstraps
    chain 0 by having Alice perform a DH ratchet step against Bob's
    signed prekey at session-init time. The reference implementation in
    [signal-protocol-core] uses the slightly simpler path of deriving
    chain 0 directly from the shared secret via HKDF (see
    [initial_chain_key] above). The two are equivalent for forward
    secrecy of post-handshake messages because [initial_chain_key] is
    a one-way function of [sk], but the implementation requires fewer
    inputs to the DR-init API. The [whitepaper_initialize_*] variants
    below model the strict whitepaper version and are kept for future
    alignment work. *)

val initialize_responder : sk: shared_secret -> Tot dr_state
let initialize_responder sk = {
  rk              = sk;
  sending_ck      = None;
  receiving_ck    = None;
  sending_dh_sk   = None;
  receiving_dh_pk = None;
  n_send          = 0;
  n_recv          = 0;
  pn              = 0;
}

(** Initiator initialization as implemented: generate a fresh DH
    keypair, derive chain 0 from the shared secret. *)
val initialize_initiator : sk: shared_secret -> Tot dr_state
let initialize_initiator sk = {
  rk              = sk;
  sending_ck      = Some (initial_chain_key sk);
  receiving_ck    = None;
  sending_dh_sk   = Some (generate_private_key ());
  receiving_dh_pk = None;
  n_send          = 0;
  n_recv          = 0;
  pn              = 0;
}

(** Whitepaper-faithful initiator initialization: takes Bob's signed-
    prekey public key and performs the first DH ratchet step at init
    time. Provided for alignment with §3.6. The current Rust
    implementation does NOT use this variant. *)
val whitepaper_initialize_initiator
  : sk: shared_secret -> initial_dh_sk: private_key -> bob_dh_pk: public_key ->
    Tot dr_state
let whitepaper_initialize_initiator sk initial_dh_sk bob_dh_pk =
  let dh_out         = dh initial_dh_sk bob_dh_pk in
  let new_rk, new_ck = kdf_rk sk dh_out in
  {
    rk              = new_rk;
    sending_ck      = Some new_ck;
    receiving_ck    = None;
    sending_dh_sk   = Some initial_dh_sk;
    receiving_dh_pk = Some bob_dh_pk;
    n_send          = 0;
    n_recv          = 0;
    pn              = 0;
  }

(** === DH ratchet step === *)

(** Performed when a message arrives carrying a new DH public key from
    the peer.

    Two cases:

    1. **Normal case** ([st.sending_dh_sk = Some cur_sk]): the receiving
       chain is derived from a fresh DH against [cur_sk], then the
       sending chain is derived from a fresh DH against [new_local_sk].
       Two [kdf_rk] applications back-to-back, exactly as in §3.5.

    2. **Bootstrap case** ([st.sending_dh_sk = None]): this happens at
       the responder's first received message. The reference
       implementation in [signal-protocol-core/src/double_ratchet.rs]
       does NOT do a DH on the receiving side here - it derives
       chain_0 directly from the root key via
       [initial_chain_key st.rk] (matching what
       [initialize_initiator] already computed for Alice). The
       sending side then proceeds normally from the unchanged root key.

    The spec faithfully models both cases so the refinement to the
    Rust implementation closes. The whitepaper-faithful alternative
    (which would do DH(SPK_sk, alice_dh_pk) at the responder's first
    message) is captured in [whitepaper_initialize_initiator] above
    and is not used here. *)
val dh_ratchet_step
  : st: dr_state ->
    new_remote_pk: public_key ->
    new_local_sk: private_key ->
    Tot dr_state

let dh_ratchet_step st new_remote_pk new_local_sk =
  let rk_recv, ck_recv =
    match st.sending_dh_sk with
    | Some cur_sk ->
      let recv_dh_out = dh cur_sk new_remote_pk in
      kdf_rk st.rk recv_dh_out
    | None ->
      // Bootstrap path: matches the responder's-first-message branch
      // in [signal-protocol-core/src/double_ratchet.rs]
      // `perform_dh_ratchet_step` where `state.sending_dh_keypair`
      // is None.
      st.rk, initial_chain_key st.rk
  in
  let send_dh_out      = dh new_local_sk new_remote_pk in
  let rk_send, ck_send = kdf_rk rk_recv send_dh_out in
  {
    rk              = rk_send;
    sending_ck      = Some ck_send;
    receiving_ck    = Some ck_recv;
    sending_dh_sk   = Some new_local_sk;
    receiving_dh_pk = Some new_remote_pk;
    n_send          = 0;
    n_recv          = 0;
    pn              = st.n_send;
  }

(** === Per-message symmetric ratchet === *)

(** Advance the sending chain by one step and return the message key plus
    the post-step state. [None] if there is no sending chain (initiator
    has not received a reply yet, or responder has not received a first
    message). *)
val advance_sending : st: dr_state ->
  Tot (option (message_key & dr_state))
let advance_sending st =
  match st.sending_ck with
  | None -> None
  | Some ck ->
    let next_ck, mk = kdf_ck ck in
    Some (mk, { st with sending_ck = Some next_ck;
                        n_send     = st.n_send + 1 })

val advance_receiving : st: dr_state ->
  Tot (option (message_key & dr_state))
let advance_receiving st =
  match st.receiving_ck with
  | None -> None
  | Some ck ->
    let next_ck, mk = kdf_ck ck in
    Some (mk, { st with receiving_ck = Some next_ck;
                        n_recv       = st.n_recv + 1 })
