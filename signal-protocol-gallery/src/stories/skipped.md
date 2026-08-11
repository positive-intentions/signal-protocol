# Skipped / out-of-order

## What this demo shows

Networks reorder packets. The Double Ratchet stores **skipped message keys** so Bob can decrypt message 2 before message 0, then still decrypt the delayed earlier message.

## Roles & materials

- Alice encrypts messages `msg-0`, `msg-1`, `msg-2` in order
- Delivery order is intentionally wrong: **2 first**, then **0**

## Step-by-step

1. **Init** — Alice initiator, Bob responder
2. **Encrypt 0..2** — Alice produces three ciphertexts
3. **Deliver msg-2 first** — Bob skips keys for 0 and 1
4. **Deliver delayed msg-0** — uses a stored skipped key
5. **Inspect** — review skipped-key count and timeline

## What to look for

- After step 3, Bob’s `skipped` count should be **2**.
- Step 4 still decrypts `msg-0` correctly.
- Timeline makes the delivery order obvious.

## API map

| Step | Core API |
|------|----------|
| 1 | `initialize_double_ratchet_internal` |
| 2 | `double_ratchet_encrypt_internal` (×3) |
| 3–4 | `double_ratchet_decrypt_internal` (skip-key path) |
