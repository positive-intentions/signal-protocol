# Key generation

## What this demo shows

How Signal Protocol key material is created before any handshake. You generate each key type one step at a time and see how public vs private material is used.

## Roles & materials

| Key | Lifetime | Who publishes it |
|-----|----------|------------------|
| Identity | Long-term | Both parties (public half in directories) |
| Signed prekey (SPK) | Medium-term | Bob publishes; rotated periodically |
| One-time prekey (OTPK) | Single use | Bob publishes a batch; Alice consumes one |
| Ephemeral | One handshake | Alice only; never reused |

## Step-by-step

1. **Identity** — `generate_identity_keypair()`
2. **Signed prekey** — `generate_signed_prekey()`
3. **One-time prekey** — `generate_one_time_prekey()`
4. **Ephemeral** — `generate_ephemeral_keypair()`
5. **Validate** — `validate_x25519_public_key` on the identity public key

Use **Show private keys** only for learning; real apps never display private material.

## What to look for

- Each step materializes one card; earlier keys stay visible.
- Teach-back explains *why* that key exists.
- Validation should succeed for a freshly generated identity public key.

## API map

| Step | Core API |
|------|----------|
| 1–4 | `generate_identity_keypair`, `generate_signed_prekey`, `generate_one_time_prekey`, `generate_ephemeral_keypair` |
| 5 | `validate_x25519_public_key` |
