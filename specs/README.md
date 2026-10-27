# Behavioural specs (Allium)

This directory holds [Allium](https://github.com/juxt/allium) behavioural specifications for `signal-protocol-core`. They describe **intended** observable behaviour and record invariants that the current code violates (see [`security/SP-2026-library-audit.md`](../security/SP-2026-library-audit.md)).

They are **not** a theorem prover and are **not** part of the Tested / Modeled / Type-checked formal-verification vocabulary used on the documentation site.

## Files

| File | Role |
| --- | --- |
| [`signal-protocol-core.allium`](./signal-protocol-core.allium) | Distilled handshake + Double Ratchet contract; finding-linked invariants |

## Optional tooling

Skills (agent workflows such as `/distill`, `/weed`, `/propagate`):

```bash
npx skills add juxt/allium
```

CLI (structural check of `.allium` files — optional, not required to build or test):

```bash
cargo install allium-cli
allium check specs/*.allium
```

Do not vendor the juxt plugin tree into this repository.

## Relationship to formal proofs

```text
Allium specs  →  audit probes / regression tests  →  ProVerif / hax stubs
(intent)         (production behaviour)              (symbolic / extract)
```

When fixing SP-2026 findings, update the matching invariants here (remove `VIOLATED` comments) and replace defect-documenting probes with positive tests.
