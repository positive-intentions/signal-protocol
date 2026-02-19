module Signal_protocol_wasm.Rust.Messages
#set-options "--fuel 0 --ifuel 1 --z3rlimit 40"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Aead in
  let open Aes.Autodetect in
  let open Aes_gcm in
  let open Aes_gcm.Private in
  let open Cipher.Block in
  let open Crypto_common in
  let open Digest.Core_api in
  let open Digest.Core_api.Ct_variable in
  let open Digest.Core_api.Wrapper in
  let open Digest.Digest in
  let open Generic_array in
  let open Hkdf in
  let open Hkdf.Errors in
  let open Hkdf.Sealed in
  let open Js_sys in
  let open Rand_core in
  let open Rand_core.Os in
  let open Sha2 in
  let open Sha2.Core_api in
  let open Signal_protocol_core.Error in
  let open Typenum in
  let open Typenum.Bit in
  let open Typenum.Marker_traits in
  let open Typenum.Private in
  let open Typenum.Type_operators in
  let open Typenum.Uint in
  ()

/// Log messages to the browser console for debugging
///
/// Provides visibility into message encryption/decryption operations
/// during development and troubleshooting.
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

/// Internal function to encrypt a message
/// This is the core logic that can be tested without WASM bindings
let encrypt_message_internal (shared_secret plaintext: t_Slice u8) (message_number: u32)
    : Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_EncryptionResult
      Signal_protocol_core.Error.t_SignalError =
  let salt:t_Array u8 (mk_usize 19) =
    let list =
      [
        mk_u8 83; mk_u8 105; mk_u8 103; mk_u8 110; mk_u8 97; mk_u8 108; mk_u8 95; mk_u8 77;
        mk_u8 101; mk_u8 115; mk_u8 115; mk_u8 97; mk_u8 103; mk_u8 101; mk_u8 95; mk_u8 83;
        mk_u8 97; mk_u8 108; mk_u8 116
      ]
    in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 19);
    Rust_primitives.Hax.array_of_list 19 list
  in
  let args:u32 = message_number <: u32 in
  let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
    let list = [Core_models.Fmt.Rt.impl__new_display #u32 args] in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
    Rust_primitives.Hax.array_of_list 1 list
  in
  let info:Alloc.String.t_String =
    Core_models.Hint.must_use #Alloc.String.t_String
      (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
              (mk_usize 1)
              (let list = ["Signal_Message_"] in
                FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                Rust_primitives.Hax.array_of_list 1 list)
              args
            <:
            Core_models.Fmt.t_Arguments)
        <:
        Alloc.String.t_String)
  in
  let hkdf:Hkdf.t_Hkdf
    (Digest.Core_api.Wrapper.t_CoreWrapper
      (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Sha2.Core_api.t_Sha256VarCore
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt
                              (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                              Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0
              ) Typenum.Bit.t_B0)
          Sha2.t_OidSha256))
    (Digest.Core_api.Wrapper.t_CoreWrapper
      (Hmac.Optim.t_HmacCore
        (Digest.Core_api.Wrapper.t_CoreWrapper
          (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Sha2.Core_api.t_Sha256VarCore
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt
                              (Typenum.Uint.t_UInt
                                  (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                  Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                      Typenum.Bit.t_B0) Typenum.Bit.t_B0)
              Sha2.t_OidSha256)))) =
    Hkdf.impl_2__new #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Sha2.Core_api.t_Sha256VarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Sha2.t_OidSha256))
      #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Hmac.Optim.t_HmacCore
          (Digest.Core_api.Wrapper.t_CoreWrapper
            (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Sha2.Core_api.t_Sha256VarCore
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt
                                    (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                    Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                        Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                Sha2.t_OidSha256))))
      (Core_models.Option.Option_Some (salt <: t_Slice u8)
        <:
        Core_models.Option.t_Option (t_Slice u8))
      shared_secret
  in
  let message_key:t_Array u8 (mk_usize 32) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32) in
  let
  (tmp0: t_Array u8 (mk_usize 32)),
  (out: Core_models.Result.t_Result Prims.unit Hkdf.Errors.t_InvalidLength) =
    Hkdf.impl_2__expand #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Sha2.Core_api.t_Sha256VarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Sha2.t_OidSha256))
      #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Hmac.Optim.t_HmacCore
          (Digest.Core_api.Wrapper.t_CoreWrapper
            (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Sha2.Core_api.t_Sha256VarCore
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt
                                    (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                    Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                        Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                Sha2.t_OidSha256))))
      hkdf
      (Alloc.String.impl_String__as_bytes info <: t_Slice u8)
      message_key
  in
  let message_key:t_Array u8 (mk_usize 32) = tmp0 in
  match
    Core_models.Result.impl__map_err #Prims.unit
      #Hkdf.Errors.t_InvalidLength
      #Signal_protocol_core.Error.t_SignalError
      #(Hkdf.Errors.t_InvalidLength -> Signal_protocol_core.Error.t_SignalError)
      out
      (fun e ->
          let e:Hkdf.Errors.t_InvalidLength = e in
          let args:Hkdf.Errors.t_InvalidLength = e <: Hkdf.Errors.t_InvalidLength in
          let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
            let list = [Core_models.Fmt.Rt.impl__new_display #Hkdf.Errors.t_InvalidLength args] in
            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
            Rust_primitives.Hax.array_of_list 1 list
          in
          Signal_protocol_core.Error.SignalError_KeyDerivation
          (Core_models.Hint.must_use #Alloc.String.t_String
              (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                      (mk_usize 1)
                      (let list = ["Message key derivation failed: "] in
                        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                        Rust_primitives.Hax.array_of_list 1 list)
                      args
                    <:
                    Core_models.Fmt.t_Arguments)
                <:
                Alloc.String.t_String))
          <:
          Signal_protocol_core.Error.t_SignalError)
    <:
    Core_models.Result.t_Result Prims.unit Signal_protocol_core.Error.t_SignalError
  with
  | Core_models.Result.Result_Ok _ ->
    let nonce_bytes:t_Array u8 (mk_usize 12) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 12) in
    let nonce_bytes:t_Array u8 (mk_usize 12) =
      Rand_core.f_fill_bytes #Rand_core.Os.t_OsRng
        #FStar.Tactics.Typeclasses.solve
        (Rand_core.Os.OsRng <: Rand_core.Os.t_OsRng)
        nonce_bytes
    in
    let key:Generic_array.t_GenericArray u8
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
          Typenum.Bit.t_B0) =
      Generic_array.impl_21__from_slice #u8
        #(Typenum.Uint.t_UInt
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                            Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Typenum.Bit.t_B0)
        (message_key <: t_Slice u8)
    in
    let cipher:Aes_gcm.t_AesGcm Aes.Autodetect.t_Aes256
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                  Typenum.Bit.t_B1) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                      Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) =
      Crypto_common.f_new #(Aes_gcm.t_AesGcm Aes.Autodetect.t_Aes256
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                        Typenum.Bit.t_B1) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                            Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0))
        #FStar.Tactics.Typeclasses.solve
        key
    in
    let nonce_ga:Generic_array.t_GenericArray u8
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                  Typenum.Bit.t_B1) Typenum.Bit.t_B0) Typenum.Bit.t_B0) =
      Generic_array.impl_21__from_slice #u8
        #(Typenum.Uint.t_UInt
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                    Typenum.Bit.t_B1) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
        (nonce_bytes <: t_Slice u8)
    in
    (match
        Core_models.Result.impl__map_err #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          #Aead.t_Error
          #Signal_protocol_core.Error.t_SignalError
          #(Aead.t_Error -> Signal_protocol_core.Error.t_SignalError)
          (Aead.f_encrypt #(Aes_gcm.t_AesGcm Aes.Autodetect.t_Aes256
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt
                              (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                              Typenum.Bit.t_B1) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt
                              (Typenum.Uint.t_UInt
                                  (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                  Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                      Typenum.Bit.t_B0))
              #FStar.Tactics.Typeclasses.solve
              #(t_Slice u8)
              cipher
              nonce_ga
              plaintext
            <:
            Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Aead.t_Error)
          (fun e ->
              let e:Aead.t_Error = e in
              let args:Aead.t_Error = e <: Aead.t_Error in
              let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
                let list = [Core_models.Fmt.Rt.impl__new_display #Aead.t_Error args] in
                FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                Rust_primitives.Hax.array_of_list 1 list
              in
              Signal_protocol_core.Error.SignalError_Encryption
              (Core_models.Hint.must_use #Alloc.String.t_String
                  (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                          (mk_usize 1)
                          (let list = ["AES-GCM encryption failed: "] in
                            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                            Rust_primitives.Hax.array_of_list 1 list)
                          args
                        <:
                        Core_models.Fmt.t_Arguments)
                    <:
                    Alloc.String.t_String))
              <:
              Signal_protocol_core.Error.t_SignalError)
        <:
        Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          Signal_protocol_core.Error.t_SignalError
      with
      | Core_models.Result.Result_Ok ciphertext ->
        let result:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Alloc.Slice.impl__to_vec #u8 (nonce_bytes <: t_Slice u8)
        in
        let result:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Alloc.Vec.impl_2__extend_from_slice #u8
            #Alloc.Alloc.t_Global
            result
            (Alloc.Vec.impl_1__as_slice ciphertext <: t_Slice u8)
        in
        Core_models.Result.Result_Ok
        ({
            Signal_protocol_wasm.Rust.Types.f_ciphertext = result;
            Signal_protocol_wasm.Rust.Types.f_message_key
            =
            Alloc.Slice.impl__to_vec #u8 (message_key <: t_Slice u8)
          }
          <:
          Signal_protocol_wasm.Rust.Types.t_EncryptionResult)
        <:
        Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_EncryptionResult
          Signal_protocol_core.Error.t_SignalError
      | Core_models.Result.Result_Err err ->
        Core_models.Result.Result_Err err
        <:
        Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_EncryptionResult
          Signal_protocol_core.Error.t_SignalError)
  | Core_models.Result.Result_Err err ->
    Core_models.Result.Result_Err err
    <:
    Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_EncryptionResult
      Signal_protocol_core.Error.t_SignalError

/// Internal function to decrypt a message
/// This is the core logic that can be tested without WASM bindings
let decrypt_message_internal (ciphertext message_key: t_Slice u8)
    : Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      Signal_protocol_core.Error.t_SignalError =
  if (Core_models.Slice.impl__len #u8 ciphertext <: usize) <. mk_usize 12
  then
    Core_models.Result.Result_Err
    (Signal_protocol_core.Error.SignalError_Decryption
      (Alloc.String.f_to_string #string
          #FStar.Tactics.Typeclasses.solve
          "Ciphertext too short (minimum 12 bytes for nonce)")
      <:
      Signal_protocol_core.Error.t_SignalError)
    <:
    Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      Signal_protocol_core.Error.t_SignalError
  else
    let nonce_ga:Generic_array.t_GenericArray u8
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                  Typenum.Bit.t_B1) Typenum.Bit.t_B0) Typenum.Bit.t_B0) =
      Generic_array.impl_21__from_slice #u8
        #(Typenum.Uint.t_UInt
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                    Typenum.Bit.t_B1) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
        (ciphertext.[ { Core_models.Ops.Range.f_end = mk_usize 12 }
            <:
            Core_models.Ops.Range.t_RangeTo usize ]
          <:
          t_Slice u8)
    in
    let encrypted_data:t_Slice u8 =
      ciphertext.[ { Core_models.Ops.Range.f_start = mk_usize 12 }
        <:
        Core_models.Ops.Range.t_RangeFrom usize ]
    in
    let key:Generic_array.t_GenericArray u8
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
          Typenum.Bit.t_B0) =
      Generic_array.impl_21__from_slice #u8
        #(Typenum.Uint.t_UInt
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                            Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Typenum.Bit.t_B0)
        message_key
    in
    let cipher:Aes_gcm.t_AesGcm Aes.Autodetect.t_Aes256
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                  Typenum.Bit.t_B1) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                      Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) =
      Crypto_common.f_new #(Aes_gcm.t_AesGcm Aes.Autodetect.t_Aes256
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                        Typenum.Bit.t_B1) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                            Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0))
        #FStar.Tactics.Typeclasses.solve
        key
    in
    match
      Core_models.Result.impl__map_err #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        #Aead.t_Error
        #Signal_protocol_core.Error.t_SignalError
        #(Aead.t_Error -> Signal_protocol_core.Error.t_SignalError)
        (Aead.f_decrypt #(Aes_gcm.t_AesGcm Aes.Autodetect.t_Aes256
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                            Typenum.Bit.t_B1) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0))
            #FStar.Tactics.Typeclasses.solve
            #(t_Slice u8)
            cipher
            nonce_ga
            encrypted_data
          <:
          Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Aead.t_Error)
        (fun e ->
            let e:Aead.t_Error = e in
            let args:Aead.t_Error = e <: Aead.t_Error in
            let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
              let list = [Core_models.Fmt.Rt.impl__new_display #Aead.t_Error args] in
              FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
              Rust_primitives.Hax.array_of_list 1 list
            in
            Signal_protocol_core.Error.SignalError_Decryption
            (Core_models.Hint.must_use #Alloc.String.t_String
                (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                        (mk_usize 1)
                        (let list = ["AES-GCM decryption failed: "] in
                          FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                          Rust_primitives.Hax.array_of_list 1 list)
                        args
                      <:
                      Core_models.Fmt.t_Arguments)
                  <:
                  Alloc.String.t_String))
            <:
            Signal_protocol_core.Error.t_SignalError)
      <:
      Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        Signal_protocol_core.Error.t_SignalError
    with
    | Core_models.Result.Result_Ok plaintext ->
      Core_models.Result.Result_Ok plaintext
      <:
      Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        Signal_protocol_core.Error.t_SignalError
    | Core_models.Result.Result_Err err ->
      Core_models.Result.Result_Err err
      <:
      Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        Signal_protocol_core.Error.t_SignalError

/// Encrypt a message using Signal Protocol message encryption
///
/// This function implements the Signal Protocol\'s message encryption scheme,
/// which provides forward secrecy by deriving a unique key for each message.
/// The encryption uses AES-GCM for authenticated encryption, ensuring both
/// confidentiality and integrity.
///
/// ## Forward Secrecy Implementation
/// Each message is encrypted with a unique key derived from:
/// - The shared secret from X3DH key exchange
/// - A message-specific counter/number
/// - Cryptographic salt and info strings
///
/// This ensures that compromise of one message key doesn\'t affect other messages.
///
/// ## Encryption Process
/// 1. Derive message-specific key using HKDF
/// 2. Generate random 96-bit nonce for AES-GCM
/// 3. Encrypt plaintext with derived key and nonce
/// 4. Prepend nonce to ciphertext for transmission
///
/// ## Security Properties
/// - **Confidentiality**: AES-256-GCM encryption
/// - **Integrity**: Built-in authentication tag
/// - **Forward Secrecy**: Unique key per message
/// - **Replay Protection**: Message numbering
///
/// ## Parameters
/// - `shared_secret`: The shared secret from X3DH key exchange (32 bytes)
/// - `plaintext`: The message to encrypt
/// - `message_number`: Sequential message counter for forward secrecy
///
/// ## Returns
/// An `EncryptionResult` containing:
/// - `ciphertext`: Nonce + encrypted data + auth tag
/// - `message_key`: The derived key for this specific message
///
/// ## Example Usage
/// ```javascript
/// const result = encrypt_message(sharedSecret, plaintext, messageNumber);
/// const encryptedData = result.ciphertext();
/// const messageKey = result.message_key();
/// ```
let encrypt_message (shared_secret plaintext: Js_sys.t_Uint8Array) (message_number: u32)
    : Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_EncryptionResult
      Wasm_bindgen.t_JsValue =
  let args:u32 = message_number <: u32 in
  let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
    let list = [Core_models.Fmt.Rt.impl__new_display #u32 args] in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
    Rust_primitives.Hax.array_of_list 1 list
  in
  let _:Prims.unit =
    log (Core_models.Ops.Deref.f_deref #Alloc.String.t_String
          #FStar.Tactics.Typeclasses.solve
          (Core_models.Hint.must_use #Alloc.String.t_String
              (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                      (mk_usize 1)
                      (let list = ["Encrypting message #"] in
                        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                        Rust_primitives.Hax.array_of_list 1 list)
                      args
                    <:
                    Core_models.Fmt.t_Arguments)
                <:
                Alloc.String.t_String)
            <:
            Alloc.String.t_String)
        <:
        string)
  in
  let shared_secret_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Signal_protocol_wasm.Rust.Crypto.uint8_array_to_vec shared_secret
  in
  let plaintext_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Signal_protocol_wasm.Rust.Crypto.uint8_array_to_vec plaintext
  in
  match
    encrypt_message_internal (Alloc.Vec.impl_1__as_slice shared_secret_bytes <: t_Slice u8)
      (Alloc.Vec.impl_1__as_slice plaintext_bytes <: t_Slice u8)
      message_number
    <:
    Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_EncryptionResult
      Signal_protocol_core.Error.t_SignalError
  with
  | Core_models.Result.Result_Ok result ->
    let args:usize =
      Alloc.Vec.impl_1__len #u8
        #Alloc.Alloc.t_Global
        result.Signal_protocol_wasm.Rust.Types.f_ciphertext
      <:
      usize
    in
    let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
      let list = [Core_models.Fmt.Rt.impl__new_display #usize args] in
      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
      Rust_primitives.Hax.array_of_list 1 list
    in
    let _:Prims.unit =
      log (Core_models.Ops.Deref.f_deref #Alloc.String.t_String
            #FStar.Tactics.Typeclasses.solve
            (Core_models.Hint.must_use #Alloc.String.t_String
                (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 2)
                        (mk_usize 1)
                        (let list = ["Message encrypted successfully, total size: "; " bytes"] in
                          FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                          Rust_primitives.Hax.array_of_list 2 list)
                        args
                      <:
                      Core_models.Fmt.t_Arguments)
                  <:
                  Alloc.String.t_String)
              <:
              Alloc.String.t_String)
          <:
          string)
    in
    Core_models.Result.Result_Ok result
    <:
    Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_EncryptionResult
      Wasm_bindgen.t_JsValue
  | Core_models.Result.Result_Err e ->
    Core_models.Result.Result_Err
    (Wasm_bindgen.impl_JsValue__from_str (Core_models.Ops.Deref.f_deref #Alloc.String.t_String
            #FStar.Tactics.Typeclasses.solve
            (Alloc.String.f_to_string #Signal_protocol_core.Error.t_SignalError
                #FStar.Tactics.Typeclasses.solve
                e
              <:
              Alloc.String.t_String)
          <:
          string))
    <:
    Core_models.Result.t_Result Signal_protocol_wasm.Rust.Types.t_EncryptionResult
      Wasm_bindgen.t_JsValue

assume
val e_': Prims.unit

unfold
let e_ = e_'

/// Encrypt a message using Signal Protocol message encryption
///
/// This function implements the Signal Protocol\'s message encryption scheme,
/// which provides forward secrecy by deriving a unique key for each message.
/// The encryption uses AES-GCM for authenticated encryption, ensuring both
/// confidentiality and integrity.
///
/// ## Forward Secrecy Implementation
/// Each message is encrypted with a unique key derived from:
/// - The shared secret from X3DH key exchange
/// - A message-specific counter/number
/// - Cryptographic salt and info strings
///
/// This ensures that compromise of one message key doesn\'t affect other messages.
///
/// ## Encryption Process
/// 1. Derive message-specific key using HKDF
/// 2. Generate random 96-bit nonce for AES-GCM
/// 3. Encrypt plaintext with derived key and nonce
/// 4. Prepend nonce to ciphertext for transmission
///
/// ## Security Properties
/// - **Confidentiality**: AES-256-GCM encryption
/// - **Integrity**: Built-in authentication tag
/// - **Forward Secrecy**: Unique key per message
/// - **Replay Protection**: Message numbering
///
/// ## Parameters
/// - `shared_secret`: The shared secret from X3DH key exchange (32 bytes)
/// - `plaintext`: The message to encrypt
/// - `message_number`: Sequential message counter for forward secrecy
///
/// ## Returns
/// An `EncryptionResult` containing:
/// - `ciphertext`: Nonce + encrypted data + auth tag
/// - `message_key`: The derived key for this specific message
///
/// ## Example Usage
/// ```javascript
/// const result = encrypt_message(sharedSecret, plaintext, messageNumber);
/// const encryptedData = result.ciphertext();
/// const messageKey = result.message_key();
/// ```
assume
val e___e_ee_wasm_bindgen_generated_encrypt_message':
    arg0_1_: u32 ->
    arg0_2_: Prims.unit ->
    arg0_3_: Prims.unit ->
    arg0_4_: Prims.unit ->
    arg1_1_: u32 ->
    arg1_2_: Prims.unit ->
    arg1_3_: Prims.unit ->
    arg1_4_: Prims.unit ->
    arg2_1_: u32 ->
    arg2_2_: Prims.unit ->
    arg2_3_: Prims.unit ->
    arg2_4_: Prims.unit
  -> Wasm_bindgen.Convert.Traits.t_WasmRet (Core_models.Result.t_Result u32 u32)

unfold
let e___e_ee_wasm_bindgen_generated_encrypt_message =
  e___e_ee_wasm_bindgen_generated_encrypt_message'

assume
val e___e_ee_wasm_bindgen_generated_encrypt_message__e_': Prims.unit

unfold
let e___e_ee_wasm_bindgen_generated_encrypt_message__e_ =
  e___e_ee_wasm_bindgen_generated_encrypt_message__e_'

/// Decrypt a message using Signal Protocol message decryption
///
/// This function decrypts messages that were encrypted using the Signal Protocol\'s
/// message encryption scheme. It uses the provided message key and extracts the
/// nonce from the ciphertext to perform AES-GCM decryption.
///
/// ## Decryption Process
/// 1. Extract 96-bit nonce from the beginning of ciphertext
/// 2. Use provided message key for AES-GCM decryption
/// 3. Verify authentication tag during decryption
/// 4. Return decrypted plaintext
///
/// ## Security Verification
/// - Authentication tag verification ensures message integrity
/// - Nonce uniqueness prevents replay attacks
/// - Key verification ensures authorized decryption
///
/// ## Parameters
/// - `shared_secret`: The original shared secret (for validation/logging)
/// - `ciphertext`: The encrypted message with prepended nonce
/// - `message_key`: The derived key for this specific message
/// - `message_number`: The message counter (for logging/validation)
///
/// ## Returns
/// A `Uint8Array` containing the decrypted plaintext message
///
/// ## Errors
/// - Returns error if ciphertext is too short (< 12 bytes for nonce)
/// - Returns error if AES-GCM decryption fails (wrong key, corrupted data, etc.)
/// - Returns error if authentication tag verification fails
///
/// ## Example Usage
/// ```javascript
/// const plaintext = decrypt_message(
///     sharedSecret,
///     encryptedData,
///     messageKey,
///     messageNumber
/// );
/// const message = new TextDecoder().decode(plaintext);
/// ```
let decrypt_message
      (shared_secret ciphertext message_key: Js_sys.t_Uint8Array)
      (message_number: u32)
    : Core_models.Result.t_Result Js_sys.t_Uint8Array Wasm_bindgen.t_JsValue =
  let args:u32 = message_number <: u32 in
  let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
    let list = [Core_models.Fmt.Rt.impl__new_display #u32 args] in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
    Rust_primitives.Hax.array_of_list 1 list
  in
  let _:Prims.unit =
    log (Core_models.Ops.Deref.f_deref #Alloc.String.t_String
          #FStar.Tactics.Typeclasses.solve
          (Core_models.Hint.must_use #Alloc.String.t_String
              (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                      (mk_usize 1)
                      (let list = ["Decrypting message #"] in
                        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                        Rust_primitives.Hax.array_of_list 1 list)
                      args
                    <:
                    Core_models.Fmt.t_Arguments)
                <:
                Alloc.String.t_String)
            <:
            Alloc.String.t_String)
        <:
        string)
  in
  let e_shared_secret_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Signal_protocol_wasm.Rust.Crypto.uint8_array_to_vec shared_secret
  in
  let ciphertext_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Signal_protocol_wasm.Rust.Crypto.uint8_array_to_vec ciphertext
  in
  let message_key_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Signal_protocol_wasm.Rust.Crypto.uint8_array_to_vec message_key
  in
  match
    decrypt_message_internal (Alloc.Vec.impl_1__as_slice ciphertext_bytes <: t_Slice u8)
      (Alloc.Vec.impl_1__as_slice message_key_bytes <: t_Slice u8)
    <:
    Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      Signal_protocol_core.Error.t_SignalError
  with
  | Core_models.Result.Result_Ok plaintext ->
    let _:Prims.unit = log "Message decrypted successfully" in
    Core_models.Result.Result_Ok
    (Core_models.Convert.f_from #Js_sys.t_Uint8Array
        #(t_Slice u8)
        #FStar.Tactics.Typeclasses.solve
        (plaintext.[ Core_models.Ops.Range.RangeFull <: Core_models.Ops.Range.t_RangeFull ]
          <:
          t_Slice u8))
    <:
    Core_models.Result.t_Result Js_sys.t_Uint8Array Wasm_bindgen.t_JsValue
  | Core_models.Result.Result_Err e ->
    Core_models.Result.Result_Err
    (Wasm_bindgen.impl_JsValue__from_str (Core_models.Ops.Deref.f_deref #Alloc.String.t_String
            #FStar.Tactics.Typeclasses.solve
            (Alloc.String.f_to_string #Signal_protocol_core.Error.t_SignalError
                #FStar.Tactics.Typeclasses.solve
                e
              <:
              Alloc.String.t_String)
          <:
          string))
    <:
    Core_models.Result.t_Result Js_sys.t_Uint8Array Wasm_bindgen.t_JsValue

assume
val e_ee_1': Prims.unit

unfold
let e_ee_1 = e_ee_1'

/// Decrypt a message using Signal Protocol message decryption
///
/// This function decrypts messages that were encrypted using the Signal Protocol\'s
/// message encryption scheme. It uses the provided message key and extracts the
/// nonce from the ciphertext to perform AES-GCM decryption.
///
/// ## Decryption Process
/// 1. Extract 96-bit nonce from the beginning of ciphertext
/// 2. Use provided message key for AES-GCM decryption
/// 3. Verify authentication tag during decryption
/// 4. Return decrypted plaintext
///
/// ## Security Verification
/// - Authentication tag verification ensures message integrity
/// - Nonce uniqueness prevents replay attacks
/// - Key verification ensures authorized decryption
///
/// ## Parameters
/// - `shared_secret`: The original shared secret (for validation/logging)
/// - `ciphertext`: The encrypted message with prepended nonce
/// - `message_key`: The derived key for this specific message
/// - `message_number`: The message counter (for logging/validation)
///
/// ## Returns
/// A `Uint8Array` containing the decrypted plaintext message
///
/// ## Errors
/// - Returns error if ciphertext is too short (< 12 bytes for nonce)
/// - Returns error if AES-GCM decryption fails (wrong key, corrupted data, etc.)
/// - Returns error if authentication tag verification fails
///
/// ## Example Usage
/// ```javascript
/// const plaintext = decrypt_message(
///     sharedSecret,
///     encryptedData,
///     messageKey,
///     messageNumber
/// );
/// const message = new TextDecoder().decode(plaintext);
/// ```
assume
val e_ee_1__e_ee_wasm_bindgen_generated_decrypt_message':
    arg0_1_: u32 ->
    arg0_2_: Prims.unit ->
    arg0_3_: Prims.unit ->
    arg0_4_: Prims.unit ->
    arg1_1_: u32 ->
    arg1_2_: Prims.unit ->
    arg1_3_: Prims.unit ->
    arg1_4_: Prims.unit ->
    arg2_1_: u32 ->
    arg2_2_: Prims.unit ->
    arg2_3_: Prims.unit ->
    arg2_4_: Prims.unit ->
    arg3_1_: u32 ->
    arg3_2_: Prims.unit ->
    arg3_3_: Prims.unit ->
    arg3_4_: Prims.unit
  -> Wasm_bindgen.Convert.Traits.t_WasmRet (Core_models.Result.t_Result u32 u32)

unfold
let e_ee_1__e_ee_wasm_bindgen_generated_decrypt_message =
  e_ee_1__e_ee_wasm_bindgen_generated_decrypt_message'

assume
val e_ee_1__e_ee_wasm_bindgen_generated_decrypt_message__e_': Prims.unit

unfold
let e_ee_1__e_ee_wasm_bindgen_generated_decrypt_message__e_ =
  e_ee_1__e_ee_wasm_bindgen_generated_decrypt_message__e_'
