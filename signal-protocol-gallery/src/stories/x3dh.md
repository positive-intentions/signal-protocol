# X3DH handshake

## What this demo shows

Extended Triple Diffie-Hellman (X3DH): Alice and Bob independently derive the **same** 32-byte shared secret from public keys + one of Alice’s ephemeral secrets, without a prior session.

## Roles & materials

- **Alice (initiator):** identity key + fresh ephemeral key
- **Bob (responder):** identity key, signed prekey, optional one-time prekey (bundle)

Toggle the **Use one-time prekey** knob to compare the 3-DH path (no OTPK) vs 4-DH path (with OTPK).

```preview
use_otpk: true
```

## Step-by-step

1. **Alice keys** — generate Alice identity + ephemeral
2. **Bob bundle** — generate Bob identity, SPK, and optional OTPK
3. **Alice initiate** — `x3dh_initiate_internal` (DH1…DH3/DH4 + HKDF)
4. **Bob respond** — `x3dh_respond_internal` with the same public inputs
5. **Compare** — shared secrets and associated data must match

## What to look for

- Alice and Bob panels fill as keys appear.
- Teach-back lists each ECDH and the final HKDF.
- **Secrets match: YES** is the success moment.

## API map

| Step | Core API |
|------|----------|
| 1–2 | `generate_*` key helpers |
| 3 | `x3dh_initiate_internal` |
| 4 | `x3dh_respond_internal` |
