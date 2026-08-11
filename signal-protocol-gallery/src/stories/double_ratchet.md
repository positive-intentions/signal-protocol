# Double Ratchet playground

## What this demo shows

After X3DH, parties run the Double Ratchet: each message advances a symmetric chain; a direction change performs a Diffie-Hellman ratchet for forward secrecy.

## Roles & materials

- Shared 32-byte root secret (here: a fixed demo secret — normally from X3DH)
- **Alice** initializes as initiator (starts with a sending chain)
- **Bob** initializes as responder (builds receiving chain on first decrypt)

```preview
plaintext: hello from Alice
```

## Step-by-step

1. **Init session** — `initialize_double_ratchet_internal` for both
2. **Alice encrypt** — first outbound message (`double_ratchet_encrypt_internal`)
3. **Bob decrypt** — first inbound triggers Bob’s DH ratchet
4. **Bob encrypt reply** — Bob now has a sending chain
5. **Alice decrypt** — Alice ratchets to receive Bob’s message

## What to look for

- Counters: `send_n` / `recv_n` and whether send/recv chains exist.
- Teach-back names “DH ratchet” vs “symmetric chain step”.
- Decrypted plaintext matches the Controls plaintext (or Bob’s fixed reply).

## API map

| Step | Core API |
|------|----------|
| 1 | `initialize_double_ratchet_internal` |
| 2, 4 | `double_ratchet_encrypt_internal` |
| 3, 5 | `double_ratchet_decrypt_internal` |
