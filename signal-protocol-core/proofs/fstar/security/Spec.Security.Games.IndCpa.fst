module Spec.Security.Games.IndCpa

(** Spec.Security.Games.IndCpa: IND-CPA game-based definitions.

    This module captures the cryptographic-game machinery that is used to
    reduce protocol security to standard cryptographic hardness
    assumptions (DDH for Curve25519, IND-CCA for AES-256-GCM, PRF for
    HKDF / HMAC-SHA-256). It is *not* on the extraction critical path;
    only the high-level security theorems (e.g. "X3DH yields an
    indistinguishable shared secret under DDH") use it.

    Status: scaffolding. The reductions themselves are the subject of a
    follow-up effort; this module fixes the signatures and assumptions so
    that the higher-level statements have something concrete to depend
    on. *)

#set-options "--fuel 0 --ifuel 1 --z3rlimit 30"

open FStar.Seq
open Spec.Crypto

(** === DDH (Decisional Diffie-Hellman) === *)

(** A DDH adversary is given (g^a, g^b, X) where X is either g^{ab} (real
    world) or a uniformly random group element (ideal world), and must
    distinguish. The advantage is the absolute difference between the two
    output probabilities.

    For the spec we model the assumption directly on [dh] / [public_key_of_private]:
    no efficient distinguisher exists between [dh sk1 (pk_of sk2)] and a
    fresh random shared secret when [sk1, sk2] are honestly sampled. *)

assume
val ddh_advantage : Type0

(** The DDH assumption: for every PPT adversary [A], its advantage in
    distinguishing real DH outputs from random shared secrets is
    negligible. Modeled here as an opaque proposition; concrete bounds
    are filled in by the cryptographic-reduction layer. *)
assume val ddh_holds : prop

(** === IND-CPA for the AEAD === *)

(** AES-256-GCM with fresh random nonces is IND-CPA. We model this as an
    abstract proposition; the formal game (left-or-right oracle, etc.)
    can be added later without changing the call sites. *)
assume val aead_ind_cpa : prop

(** === PRF security of HKDF / HMAC-SHA-256 === *)

assume val hkdf_is_prf : prop
assume val hmac_sha256_is_prf : prop
