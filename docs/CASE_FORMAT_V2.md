# Case Format v2

This document explains why SP-DIFFER needs case format v2, what problem each new field solves, and what is intentionally still out of scope.

## What Drove The Design

The design is based on the pinned official BIP 352 vector snapshot under `tests/vectors/bip352/official/`, not on hypothetical future needs.

From that snapshot:

- sending-side input mix: `40` `P2PKH`, `11` `P2TR`, `3` `P2WPKH`, `3` `P2SH-P2WPKH`
- receiving-side input mix: `42` `P2PKH`, `11` `P2TR`, `3` `P2WPKH`, `3` `P2SH-P2WPKH`
- sending entries with more than one recipient group: `4`
- receiving output list sizes: `1`, `2`, `3`, `4`, and `2324`
- receiving label list sizes: `0`, `1`, `2`, and `3`
- non-empty `scriptSig` fields across the snapshot: `88`
- non-empty `txinwitness` fields across the snapshot: `32`

Those numbers came from the local analysis scripts over the vendored official vectors.

## What v1 Could Not Express

v1 was intentionally small, but it collapsed several pieces of information that the official vectors test explicitly:

- `P2PKH` was reduced away entirely.
- Multiple recipient groups had to be flattened into one global `(scan, spend)` pair.
- Receiver-side scanning inputs were missing because the format had no outputs-to-scan section.
- Receiver key material was missing.
- Input pubkey extraction context was missing.

That is why only a narrow sender-side subset was projectable into v1.

## Chosen v2 Shape

The v2 format adds five capabilities:

1. `P2PKH` as a first-class input type.
2. Recipient groups as a repeated section with a `count`.
3. Outputs-to-scan as repeated x-only pubkeys.
4. Receiver scan/spend private keys.
5. Raw extraction context on each input:
   - previous-output `scriptPubKey`
   - `scriptSig`
   - `txinwitness`

The binary contract is specified in `../spec/FORMAT_V2.md`.

## Why This Is The Right Scope

The new fields are enough to model the official gaps without trying to solve later reporting problems in the case payload itself.

What v2 does cover:

- full input classification needed by the official vectors
- grouped recipients for sender-side derivation cases
- receiver-side scanning inputs and private key material
- labels in the same payload as the key material they depend on

What v2 does not try to solve yet:

- output artifact/report format v2
- embedding official case indices inside the binary payload
- semantic comparison against expected tweaks/shared secrets
- runner and worker execution of v2 cases

Those are separate milestones and are safer to add after the case contract is stable.

## Rollout Plan

1. Land the versioned v2 parser and fixtures.
2. Keep the current runner/worker execution path on v1 while v2 stabilizes.
3. Add a v2-aware oracle/vector runner before asking workers to execute v2 cases directly.
4. Upgrade worker adapters only after the expected-output comparison contract is ready.

Steps 1 through 4 are now in place, and the semantic execution path also has a separate compiled semantic worker ABI. The remaining gap is no longer format expressiveness or ABI shape; it is broadening semantic-worker coverage, improving replay/report ergonomics, and using that stable execution surface for regression generation and fuzzing.

## Canonical Example

`tests/vectors/example_v2.hex` is a composite, human-sized example that exercises all major v2 additions in one payload:

- one `P2PKH` input with previous-output script, `scriptSig`, and `txinwitness`
- two recipient groups
- one output-to-scan
- receiver key material
- two labels

The keys and scripts are drawn from the official vector snapshot, but the example is intentionally smaller than the largest official cases so it stays readable.
