# Full session

## What this demo shows

The complete happy path: **X3DH handshake → Double Ratchet init → bidirectional messaging**, with a chat-style transcript of decrypted plaintext.

## Roles & materials

- Alice initiates X3DH (identity + ephemeral)
- Bob publishes identity, signed prekey, one-time prekey
- Shared secret seeds both Double Ratchet states

```preview
alice_msg: Hi Bob — sealed with Signal.
bob_msg: Hey Alice — ratchet works.
```

## Step-by-step

1. **X3DH** — initiate + respond; verify secrets match
2. **Init DR** — Alice initiator, Bob responder from the shared secret
3. **Alice → Bob** — encrypt/decrypt using Controls `alice_msg`
4. **Bob → Alice** — encrypt/decrypt using Controls `bob_msg`
5. **Send again** — repeat Alice→Bob then Bob→Alice (messaging phase)

## What to look for

- Phase label switches from **Handshake** to **Messaging**.
- Bubbles show cleartext only after successful decrypt.
- Teach-back ties each UI step to core APIs.

## API map

| Step | Core API |
|------|----------|
| 1 | `x3dh_initiate_internal`, `x3dh_respond_internal` |
| 2 | `initialize_double_ratchet_internal` |
| 3–5 | `double_ratchet_encrypt_internal`, `double_ratchet_decrypt_internal` |
