/-
Abstract Cryptographic Primitives for Signal Protocol Verification (Aeneas Lean 4)

This module provides abstract models of cryptographic operations
used in the Signal Protocol, adapted for the Aeneas extraction style.
-/

namespace AbstractCrypto

abbrev Bytes := ByteArray

structure PrivateKey where
  data : Bytes
  valid : data.size = 32

structure PublicKey where
  data : Bytes
  valid : data.size = 32

structure Signature where
  data : Bytes
  valid : data.size = 64

structure SharedSecret where
  data : Bytes
  valid : data.size = 32

def isValidPrivateKey (b : Bytes) : Bool := b.size == 32

def isValidPublicKey (b : Bytes) : Bool := b.size == 32

def isValidSignature (b : Bytes) : Bool := b.size == 64

axiom generatePrivateKey : Unit → PrivateKey

axiom publicKeyOfPrivate : PrivateKey → PublicKey

axiom dh : PrivateKey → PublicKey → SharedSecret

axiom sign : PrivateKey → Bytes → Signature

axiom verify : PublicKey → Signature → Bytes → Bool

axiom hkdfDerive : Bytes → Bytes → Bytes → Nat → Except String Bytes

axiom aeadEncrypt : Bytes → Bytes → Bytes → Bytes → Except String Bytes

axiom aeadDecrypt : Bytes → Bytes → Bytes → Bytes → Except String Bytes

axiom generatePrivateKey_valid (u : Unit) : (generatePrivateKey u).data.size = 32

axiom publicKeyOfPrivate_valid (sk : PrivateKey) :
  isValidPrivateKey sk.data → isValidPublicKey (publicKeyOfPrivate sk).data

axiom dh_commutativity (sk1 sk2 : PrivateKey) :
  isValidPrivateKey sk1.data →
  isValidPrivateKey sk2.data →
  dh sk1 (publicKeyOfPrivate sk2) = dh sk2 (publicKeyOfPrivate sk1)

axiom dh_deterministic (sk : PrivateKey) (pk : PublicKey) :
  dh sk pk = dh sk pk

axiom dh_produces_shared_secret (sk : PrivateKey) (pk : PublicKey) :
  isValidPrivateKey sk.data →
  isValidPublicKey pk.data →
  (dh sk pk).data.size = 32

axiom sign_verify_correct (sk : PrivateKey) (data : Bytes) :
  isValidPrivateKey sk.data →
  verify (publicKeyOfPrivate sk) (sign sk data) data = true

axiom sign_produces_signature (sk : PrivateKey) (data : Bytes) :
  isValidPrivateKey sk.data →
  isValidSignature (sign sk data).data

axiom verify_rejects_wrong_key (sk1 sk2 : PrivateKey) (data : Bytes) :
  isValidPrivateKey sk1.data →
  isValidPrivateKey sk2.data →
  sk1 ≠ sk2 →
  verify (publicKeyOfPrivate sk1) (sign sk2 data) data = false

axiom key_injection (sk1 sk2 : PrivateKey) :
  isValidPrivateKey sk1.data →
  isValidPrivateKey sk2.data →
  sk1 ≠ sk2 →
  publicKeyOfPrivate sk1 ≠ publicKeyOfPrivate sk2

axiom key_injection_inverse (sk1 sk2 : PrivateKey) :
  isValidPrivateKey sk1.data →
  isValidPrivateKey sk2.data →
  publicKeyOfPrivate sk1 = publicKeyOfPrivate sk2 →
  sk1 = sk2

axiom forward_secrecy_dh (identitySk ephemeralSk : PrivateKey) (pk : PublicKey) :
  isValidPrivateKey identitySk.data →
  isValidPrivateKey ephemeralSk.data →
  isValidPublicKey pk.data →
  identitySk ≠ ephemeralSk →
  dh ephemeralSk pk ≠ dh identitySk pk

axiom hkdf_output_length (salt ikm info : Bytes) (len : Nat) :
  match hkdfDerive salt ikm info len with
  | Except.ok output => output.size = len
  | Except.error _ => True

axiom hkdf_deterministic (salt ikm info : Bytes) (len : Nat) :
  hkdfDerive salt ikm info len = hkdfDerive salt ikm info len

axiom aead_round_trip (key plaintext aad nonce : Bytes) :
  match aeadEncrypt key plaintext aad nonce with
  | Except.ok ciphertext => aeadDecrypt key ciphertext aad nonce = Except.ok plaintext
  | Except.error _ => True

axiom x3dh_key_agreement
    (aliceIkSk aliceEkSk bobIkSk bobSpkSk : PrivateKey) :
  isValidPrivateKey aliceIkSk.data →
  isValidPrivateKey aliceEkSk.data →
  isValidPrivateKey bobIkSk.data →
  isValidPrivateKey bobSpkSk.data →
  let aliceIkPk := publicKeyOfPrivate aliceIkSk
  let aliceEkPk := publicKeyOfPrivate aliceEkSk
  let bobIkPk := publicKeyOfPrivate bobIkSk
  let bobSpkPk := publicKeyOfPrivate bobSpkSk
  dh aliceIkSk bobSpkPk = dh bobSpkSk aliceIkPk ∧
  dh aliceEkSk bobIkPk = dh bobIkSk aliceEkPk ∧
  dh aliceEkSk bobSpkPk = dh bobSpkSk aliceEkPk

axiom x3dh_key_agreement_with_opk (aliceEkSk bobOpkSk : PrivateKey) :
  isValidPrivateKey aliceEkSk.data →
  isValidPrivateKey bobOpkSk.data →
  let aliceEphemeralPk := publicKeyOfPrivate aliceEkSk
  let bobOpkPk := publicKeyOfPrivate bobOpkSk
  dh aliceEkSk bobOpkPk = dh bobOpkSk aliceEphemeralPk

def emptyBytes : Bytes := ByteArray.empty

def concatBytes (a b : Bytes) : Bytes := a ++ b

def zeroBytes (len : Nat) : Bytes := ByteArray.mk ((List.replicate len (0 : UInt8)).toArray)

def sliceBytes (b : Bytes) (start len : Nat) (_ : start + len ≤ b.size) : Bytes :=
  (b.extract start (start + len))

end AbstractCrypto
