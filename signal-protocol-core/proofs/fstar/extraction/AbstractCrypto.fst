module AbstractCrypto

(** AbstractCrypto: backward-compatibility shim.

    This module exists solely because the [#[hax_lib::fstar::replace_body(...)]]
    annotations in [signal-protocol-core/src/crypto.rs] and [keys.rs] still
    reference symbols by the names [AbstractCrypto.dh],
    [AbstractCrypto.bytes_to_vec], [AbstractCrypto.hkdf_derive_vec], etc.

    The canonical definitions live in [Spec.Crypto]. New verification
    work should target [Spec.Crypto] directly; in particular the
    refinement proofs in [Spec.X3DH] and [Spec.DoubleRatchet] rely on
    [Spec.Crypto] alone.

    Future work may replace the raw [replace_body] strings with
    structured [#[hax_lib::ensures]] contracts and narrow this shim. *)

#set-options "--fuel 0 --ifuel 1 --z3rlimit 30"

open FStar.Seq
open Rust_primitives
open Rust_primitives.Integers

(** Re-export everything from Spec.Crypto: [bytes], [private_key],
    [public_key], [signature], [shared_secret], [aead_key], [nonce],
    [dh], [dh_commutativity], [public_key_of_private],
    [generate_private_key], [sign], [verify], [sign_verify_correct],
    [hkdf], [hmac_sha256], [aead_encrypt], [aead_decrypt],
    [aead_correctness]. *)
include Spec.Crypto

(** === hax-extraction bridge helpers === *)

(** Convert a [Spec.Crypto.bytes] into a hax [Alloc.Vec.t_Vec u8 _].
    Used wherever the extracted Rust code expects a [Vec<u8>] but the
    abstract crypto operates on [Seq.seq u8]. *)
let bytes_to_vec (b: bytes) : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  Alloc.Slice.impl__to_vec #u8 (b <: t_Slice u8)

(** [hkdf_derive] returning a [Result] (matches the Rust function
    signature [Result<Vec<u8>, SignalError>]). The pure underlying
    [hkdf] is total and never errors in the spec, so this always
    returns [Ok]. *)
let hkdf_derive_vec
    (salt ikm info: bytes)
    (len: usize)
  : Core_models.Result.t_Result
      (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      Signal_protocol_core.Error.t_SignalError
=
  Core_models.Result.Result_Ok (bytes_to_vec (hkdf salt ikm info (v len)))
