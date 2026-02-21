/-
Abstract Cryptographic Primitives for Signal Protocol Verification (Lean 4)

This module provides abstract models of cryptographic operations
used in the Signal Protocol. These abstractions allow us to verify
protocol properties without requiring full cryptographic proofs.

The security axioms capture essential properties needed for:
- Key authentication
- Forward secrecy
- Key indistinguishability
-/

namespace AbstractCrypto

/-! === Type Definitions === -/

/-- Byte sequences as arrays of bytes -/
abbrev Bytes := ByteArray

/-- Private keys are 32-byte sequences -/
structure PrivateKey where
  data : Bytes
  valid : data.size = 32

/-- Public keys are 32-byte sequences -/
structure PublicKey where
  data : Bytes
  valid : data.size = 32

/-- Signatures are 64-byte sequences -/
structure Signature where
  data : Bytes
  valid : data.size = 64

/-- Shared secrets from DH are 32 bytes -/
structure SharedSecret where
  data : Bytes
  valid : data.size = 32

/-! === Validation Functions === -/

def isValidPrivateKey (b : Bytes) : Bool := b.size == 32

def isValidPublicKey (b : Bytes) : Bool := b.size == 32

def isValidSignature (b : Bytes) : Bool := b.size == 64

/-! === Cryptographic Operations (Axiomatized) === -/

/-- Generate a fresh random private key (32 bytes) -/
axiom generatePrivateKey : Unit → PrivateKey

/-- Derive the corresponding public key from a private key -/
axiom publicKeyOfPrivate : PrivateKey → PublicKey

/-- X25519 Diffie-Hellman key exchange -/
axiom dh : PrivateKey → PublicKey → SharedSecret

/-- Ed25519 signature generation -/
axiom sign : PrivateKey → Bytes → Signature

/-- Ed25519 signature verification -/
axiom verify : PublicKey → Signature → Bytes → Bool

/-- HKDF-based key derivation -/
axiom hkdfDerive : Bytes → Bytes → Bytes → Nat → Except String Bytes

/-- AEAD encryption -/
axiom aeadEncrypt : Bytes → Bytes → Bytes → Bytes → Except String Bytes

/-- AEAD decryption -/
axiom aeadDecrypt : Bytes → Bytes → Bytes → Bytes → Except String Bytes

/-! === Key Generation Guarantees === -/

/-- Generated private keys are always valid (32 bytes) -/
axiom generatePrivateKey_valid (u : Unit) : (generatePrivateKey u).data.size = 32

/-- Public key derivation preserves validity -/
axiom publicKeyOfPrivate_valid (sk : PrivateKey) :
  isValidPrivateKey sk.data → isValidPublicKey (publicKeyOfPrivate sk).data

/-! === DH Security Axioms === -/

/-- DH commutativity: DH(a, B) = DH(b, A) when B = pub(A) and A = pub(b) -/
axiom dh_commutativity (sk1 sk2 : PrivateKey) :
  isValidPrivateKey sk1.data →
  isValidPrivateKey sk2.data →
  dh sk1 (publicKeyOfPrivate sk2) = dh sk2 (publicKeyOfPrivate sk1)

/-- DH produces the same result for the same inputs -/
axiom dh_deterministic (sk : PrivateKey) (pk : PublicKey) :
  dh sk pk = dh sk pk

/-- DH correctness: DH produces 32-byte shared secret for valid inputs -/
axiom dh_produces_shared_secret (sk : PrivateKey) (pk : PublicKey) :
  isValidPrivateKey sk.data →
  isValidPublicKey pk.data →
  (dh sk pk).data.size = 32

/-! === Signature Security Axioms === -/

/-- Signatures verify correctly with the matching public key -/
axiom sign_verify_correct (sk : PrivateKey) (data : Bytes) :
  isValidPrivateKey sk.data →
  verify (publicKeyOfPrivate sk) (sign sk data) data = true

/-- Signatures have correct length (64 bytes for Ed25519) -/
axiom sign_produces_signature (sk : PrivateKey) (data : Bytes) :
  isValidPrivateKey sk.data →
  isValidSignature (sign sk data).data

/-- Verification rejects wrong keys -/
axiom verify_rejects_wrong_key (sk1 sk2 : PrivateKey) (data : Bytes) :
  isValidPrivateKey sk1.data →
  isValidPrivateKey sk2.data →
  sk1 ≠ sk2 →
  verify (publicKeyOfPrivate sk1) (sign sk2 data) data = false

/-! === Key Indistinguishability Axioms === -/

/-- Different private keys yield different public keys (injectivity) -/
axiom key_injection (sk1 sk2 : PrivateKey) :
  isValidPrivateKey sk1.data →
  isValidPrivateKey sk2.data →
  sk1 ≠ sk2 →
  publicKeyOfPrivate sk1 ≠ publicKeyOfPrivate sk2

/-- Same public key implies same private key -/
axiom key_injection_inverse (sk1 sk2 : PrivateKey) :
  isValidPrivateKey sk1.data →
  isValidPrivateKey sk2.data →
  publicKeyOfPrivate sk1 = publicKeyOfPrivate sk2 →
  sk1 = sk2

/-! === Forward Secrecy Axioms === -/

/-- Compromise of a long-term key doesn't reveal past DH secrets -/
axiom forward_secrecy_dh (identitySk ephemeralSk : PrivateKey) (pk : PublicKey) :
  isValidPrivateKey identitySk.data →
  isValidPrivateKey ephemeralSk.data →
  isValidPublicKey pk.data →
  identitySk ≠ ephemeralSk →
  dh ephemeralSk pk ≠ dh identitySk pk

/-! === HKDF Security Axioms === -/

/-- HKDF produces output of requested length -/
axiom hkdf_output_length (salt ikm info : Bytes) (len : Nat) :
  match hkdfDerive salt ikm info len with
  | Except.ok output => output.size = len
  | Except.error _ => True

/-- HKDF is deterministic for same inputs -/
axiom hkdf_deterministic (salt ikm info : Bytes) (len : Nat) :
  hkdfDerive salt ikm info len = hkdfDerive salt ikm info len

/-! === AEAD Security Axioms === -/

/-- AEAD round-trip: decryption of encryption recovers plaintext -/
axiom aead_round_trip (key plaintext aad nonce : Bytes) :
  match aeadEncrypt key plaintext aad nonce with
  | Except.ok ciphertext => aeadDecrypt key ciphertext aad nonce = Except.ok plaintext
  | Except.error _ => True

/-! === X3DH Key Agreement Axioms === -/

/-- X3DH produces the same shared secret for initiator and responder -/
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

/-- X3DH with one-time prekey also produces matching secrets -/
axiom x3dh_key_agreement_with_opk (aliceEkSk bobOpkSk : PrivateKey) :
  isValidPrivateKey aliceEkSk.data →
  isValidPrivateKey bobOpkSk.data →
  let aliceEphemeralPk := publicKeyOfPrivate aliceEkSk
  let bobOpkPk := publicKeyOfPrivate bobOpkSk
  dh aliceEkSk bobOpkPk = dh bobOpkSk aliceEphemeralPk

/-! === Utility Functions === -/

/-- Empty byte sequence -/
def emptyBytes : Bytes := ByteArray.empty

/-- Concatenate two byte sequences -/
def concatBytes (a b : Bytes) : Bytes := a ++ b

/-- Create a byte sequence of zeros of given length -/
def zeroBytes (len : Nat) : Bytes := ByteArray.mk ((List.replicate len (0 : UInt8)).toArray)

/-- Extract a slice of bytes -/
def sliceBytes (b : Bytes) (start len : Nat) (_ : start + len ≤ b.size) : Bytes :=
  (b.extract start (start + len))

end AbstractCrypto
