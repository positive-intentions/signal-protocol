module Signal_protocol_wasm.Rust.Keys
#set-options "--fuel 0 --ifuel 1 --z3rlimit 40"
open FStar.Mul
open Core_models

let log (s: string) : Prims.unit =
  let args:string = s <: string in
  let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
    let list = [Core_models.Fmt.Rt.impl__new_display #string args] in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
    Rust_primitives.Hax.array_of_list 1 list
  in
  let _:Prims.unit =
    Std.Io.Stdio.e_eprint (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 2)
          (mk_usize 1)
          (let list = [""; "\n"] in
            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
            Rust_primitives.Hax.array_of_list 2 list)
          args
        <:
        Core_models.Fmt.t_Arguments)
  in
  let _:Prims.unit = () in
  ()

/// Internal function to generate an X25519 key pair - delegates to core
let generate_x25519_keypair_internal (_: Prims.unit) : Signal_protocol_wasm.Rust.Types.t_KeyPair =
  let core_keypair:Signal_protocol_core.Types.t_KeyPair =
    Signal_protocol_core.Keys.generate_identity_keypair ()
  in
  {
    Signal_protocol_wasm.Rust.Types.f_public_key
    =
    core_keypair.Signal_protocol_core.Types.f_public_key;
    Signal_protocol_wasm.Rust.Types.f_private_key
    =
    core_keypair.Signal_protocol_core.Types.f_private_key
  }
  <:
  Signal_protocol_wasm.Rust.Types.t_KeyPair

/// Generate an identity key pair for long-term user identification
/// Identity keys are long-lived keys that identify a user or device.
/// They are used in the X3DH key exchange protocol and for signing
/// other keys to establish authenticity.
/// ## Implementation
/// Uses X25519 (Curve25519 Diffie-Hellman) for key agreement operations.
/// This provides 128-bit security level with efficient constant-time operations.
/// ## Security Properties
/// - Uses OS-level entropy source (OsRng)
/// - Generates proper Curve25519 scalar/point pair
/// - Public key is valid curve point derived via scalar multiplication
/// - Constant-time operations prevent timing attacks
/// ## Usage
/// Each user/device should generate one identity key pair and use it
/// consistently across all communication sessions. The public key
/// can be distributed through a key server or other trusted mechanism.
/// ## Returns
/// A `KeyPair` containing the identity public and private keys (32 bytes each)
let generate_identity_keypair (_: Prims.unit)
    : Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_KeyPair Wasm_bindgen.t_JsValue =
  let _:Prims.unit = log "Generating identity keypair using X25519" in
  Core_models.Result.Result_Ok (generate_x25519_keypair_internal ())
  <:
  Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_KeyPair Wasm_bindgen.t_JsValue

assume
val e_': Prims.unit

unfold
let e_ = e_'

/// Generate an identity key pair for long-term user identification
/// Identity keys are long-lived keys that identify a user or device.
/// They are used in the X3DH key exchange protocol and for signing
/// other keys to establish authenticity.
/// ## Implementation
/// Uses X25519 (Curve25519 Diffie-Hellman) for key agreement operations.
/// This provides 128-bit security level with efficient constant-time operations.
/// ## Security Properties
/// - Uses OS-level entropy source (OsRng)
/// - Generates proper Curve25519 scalar/point pair
/// - Public key is valid curve point derived via scalar multiplication
/// - Constant-time operations prevent timing attacks
/// ## Usage
/// Each user/device should generate one identity key pair and use it
/// consistently across all communication sessions. The public key
/// can be distributed through a key server or other trusted mechanism.
/// ## Returns
/// A `KeyPair` containing the identity public and private keys (32 bytes each)
assume
val e___e_ee_wasm_bindgen_generated_generate_identity_keypair': Prims.unit
  -> Wasm_bindgen.Convert.Traits.t_WasmRet (Core_models.Result.t_Result u32 u32)

unfold
let e___e_ee_wasm_bindgen_generated_generate_identity_keypair =
  e___e_ee_wasm_bindgen_generated_generate_identity_keypair'

assume
val e___e_ee_wasm_bindgen_generated_generate_identity_keypair__e_': Prims.unit

unfold
let e___e_ee_wasm_bindgen_generated_generate_identity_keypair__e_ =
  e___e_ee_wasm_bindgen_generated_generate_identity_keypair__e_'

/// Generate a signed prekey for medium-term use in key exchanges
/// Signed prekeys are generated periodically (e.g., weekly) and signed
/// by the identity key to prove authenticity. They are used in the X3DH
/// protocol to establish initial communication.
/// ## Implementation
/// Uses X25519 (Curve25519 Diffie-Hellman) for key agreement operations.
/// ## Purpose
/// - Provides forward secrecy by rotating regularly
/// - Enables asynchronous key exchange when recipient is offline
/// - Signed by identity key for authenticity verification
/// ## Security Properties
/// - Real elliptic curve cryptography (X25519)
/// - Constant-time operations
/// - Proper scalar/point derivation
/// ## Returns
/// A `KeyPair` containing the signed prekey public and private keys (32 bytes each)
let generate_signed_prekey (_: Prims.unit)
    : Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_KeyPair Wasm_bindgen.t_JsValue =
  let _:Prims.unit = log "Generating signed prekey using X25519" in
  Core_models.Result.Result_Ok (generate_x25519_keypair_internal ())
  <:
  Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_KeyPair Wasm_bindgen.t_JsValue

assume
val e_ee_1': Prims.unit

unfold
let e_ee_1 = e_ee_1'

/// Generate a signed prekey for medium-term use in key exchanges
/// Signed prekeys are generated periodically (e.g., weekly) and signed
/// by the identity key to prove authenticity. They are used in the X3DH
/// protocol to establish initial communication.
/// ## Implementation
/// Uses X25519 (Curve25519 Diffie-Hellman) for key agreement operations.
/// ## Purpose
/// - Provides forward secrecy by rotating regularly
/// - Enables asynchronous key exchange when recipient is offline
/// - Signed by identity key for authenticity verification
/// ## Security Properties
/// - Real elliptic curve cryptography (X25519)
/// - Constant-time operations
/// - Proper scalar/point derivation
/// ## Returns
/// A `KeyPair` containing the signed prekey public and private keys (32 bytes each)
assume
val e_ee_1__e_ee_wasm_bindgen_generated_generate_signed_prekey': Prims.unit
  -> Wasm_bindgen.Convert.Traits.t_WasmRet (Core_models.Result.t_Result u32 u32)

unfold
let e_ee_1__e_ee_wasm_bindgen_generated_generate_signed_prekey =
  e_ee_1__e_ee_wasm_bindgen_generated_generate_signed_prekey'

assume
val e_ee_1__e_ee_wasm_bindgen_generated_generate_signed_prekey__e_': Prims.unit

unfold
let e_ee_1__e_ee_wasm_bindgen_generated_generate_signed_prekey__e_ =
  e_ee_1__e_ee_wasm_bindgen_generated_generate_signed_prekey__e_'

/// Generate a one-time prekey for single-use in key exchanges
/// One-time prekeys provide additional forward secrecy by being used only once.
/// They are consumed during the X3DH key exchange and then discarded,
/// ensuring that compromise of long-term keys doesn\'t affect past communications.
/// ## Implementation
/// Uses X25519 (Curve25519 Diffie-Hellman) for key agreement operations.
/// ## Security Benefits
/// - Perfect forward secrecy (used only once)
/// - Prevents replay attacks on key exchanges
/// - Protects against compromise of identity/signed prekeys
/// - Real elliptic curve cryptography
/// ## Returns
/// A `KeyPair` containing the one-time prekey public and private keys (32 bytes each)
let generate_one_time_prekey (_: Prims.unit)
    : Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_KeyPair Wasm_bindgen.t_JsValue =
  let _:Prims.unit = log "Generating one-time prekey using X25519" in
  Core_models.Result.Result_Ok (generate_x25519_keypair_internal ())
  <:
  Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_KeyPair Wasm_bindgen.t_JsValue

assume
val e_ee_2': Prims.unit

unfold
let e_ee_2 = e_ee_2'

/// Generate a one-time prekey for single-use in key exchanges
/// One-time prekeys provide additional forward secrecy by being used only once.
/// They are consumed during the X3DH key exchange and then discarded,
/// ensuring that compromise of long-term keys doesn\'t affect past communications.
/// ## Implementation
/// Uses X25519 (Curve25519 Diffie-Hellman) for key agreement operations.
/// ## Security Benefits
/// - Perfect forward secrecy (used only once)
/// - Prevents replay attacks on key exchanges
/// - Protects against compromise of identity/signed prekeys
/// - Real elliptic curve cryptography
/// ## Returns
/// A `KeyPair` containing the one-time prekey public and private keys (32 bytes each)
assume
val e_ee_2__e_ee_wasm_bindgen_generated_generate_one_time_prekey': Prims.unit
  -> Wasm_bindgen.Convert.Traits.t_WasmRet (Core_models.Result.t_Result u32 u32)

unfold
let e_ee_2__e_ee_wasm_bindgen_generated_generate_one_time_prekey =
  e_ee_2__e_ee_wasm_bindgen_generated_generate_one_time_prekey'

assume
val e_ee_2__e_ee_wasm_bindgen_generated_generate_one_time_prekey__e_': Prims.unit

unfold
let e_ee_2__e_ee_wasm_bindgen_generated_generate_one_time_prekey__e_ =
  e_ee_2__e_ee_wasm_bindgen_generated_generate_one_time_prekey__e_'

/// Generate an ephemeral key pair for temporary use in key exchanges
/// Ephemeral keys are generated fresh for each key exchange session
/// and provide additional forward secrecy. They are never stored
/// long-term and are discarded after the key exchange completes.
/// ## Implementation
/// Uses X25519 (Curve25519 Diffie-Hellman) for key agreement operations.
/// ## Use Cases
/// - X3DH key exchange initiation
/// - Session-specific entropy
/// - Enhanced forward secrecy guarantees
/// ## Security Properties
/// - Real elliptic curve cryptography (X25519)
/// - Constant-time operations
/// - Fresh randomness for each generation
/// ## Returns
/// A `KeyPair` containing the ephemeral public and private keys (32 bytes each)
let generate_ephemeral_keypair (_: Prims.unit)
    : Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_KeyPair Wasm_bindgen.t_JsValue =
  let _:Prims.unit = log "Generating ephemeral keypair using X25519" in
  Core_models.Result.Result_Ok (generate_x25519_keypair_internal ())
  <:
  Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_KeyPair Wasm_bindgen.t_JsValue

assume
val e_ee_3': Prims.unit

unfold
let e_ee_3 = e_ee_3'

/// Generate an ephemeral key pair for temporary use in key exchanges
/// Ephemeral keys are generated fresh for each key exchange session
/// and provide additional forward secrecy. They are never stored
/// long-term and are discarded after the key exchange completes.
/// ## Implementation
/// Uses X25519 (Curve25519 Diffie-Hellman) for key agreement operations.
/// ## Use Cases
/// - X3DH key exchange initiation
/// - Session-specific entropy
/// - Enhanced forward secrecy guarantees
/// ## Security Properties
/// - Real elliptic curve cryptography (X25519)
/// - Constant-time operations
/// - Fresh randomness for each generation
/// ## Returns
/// A `KeyPair` containing the ephemeral public and private keys (32 bytes each)
assume
val e_ee_3__e_ee_wasm_bindgen_generated_generate_ephemeral_keypair': Prims.unit
  -> Wasm_bindgen.Convert.Traits.t_WasmRet (Core_models.Result.t_Result u32 u32)

unfold
let e_ee_3__e_ee_wasm_bindgen_generated_generate_ephemeral_keypair =
  e_ee_3__e_ee_wasm_bindgen_generated_generate_ephemeral_keypair'

assume
val e_ee_3__e_ee_wasm_bindgen_generated_generate_ephemeral_keypair__e_': Prims.unit

unfold
let e_ee_3__e_ee_wasm_bindgen_generated_generate_ephemeral_keypair__e_ =
  e_ee_3__e_ee_wasm_bindgen_generated_generate_ephemeral_keypair__e_'
