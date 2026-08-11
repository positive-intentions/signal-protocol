# Error surface

## What this demo shows

A guided tour of **failure modes**. Each step feeds invalid input into `signal-protocol-core` and records the `SignalError` (or verify-false) so you can recognize bad material during testing.

## Roles & materials

No lasting session — each step is an isolated negative test with freshly generated valid keys where needed, then one deliberate fault.

## Step-by-step

1. **Bad pubkey length** — `validate_x25519_public_key` on 3 bytes
2. **X3DH bad prekey** — truncated signed-prekey public key
3. **DR init bad secret** — 16-byte root instead of 32
4. **Tampered ciphertext** — flip a ciphertext byte after encrypt
5. **Wrong verify key** — sign with key A, verify with key B

## What to look for

- Every step should fail (or verify false) — that is success for this demo.
- Error strings name the subsystem (`Invalid input`, `Decryption`, etc.).
- Teach-back explains *why* the input is illegal.

## API map

| Step | Core API |
|------|----------|
| 1 | `validate_x25519_public_key` |
| 2 | `x3dh_initiate_internal` |
| 3 | `initialize_double_ratchet_internal` |
| 4 | `double_ratchet_encrypt_internal` / `double_ratchet_decrypt_internal` |
| 5 | `sign_data_internal` / `verify_signature_internal` |
