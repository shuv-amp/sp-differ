# Reference Oracle

SP-DIFFER now vendors the upstream BIP 352 reference implementation snapshot together with the official send-and-receive vectors it was pinned against.

## Why This Exists

The project previously had:

- a strict local case/output contract,
- byte-worker libraries that agreed on that contract,
- a pinned official vector snapshot,
- but no pinned semantic oracle inside the repo.

That meant the repo could say what the official vectors looked like, but it could not independently re-run the upstream semantics offline from the same checkout.

The vendored reference bundle fixes that.

## What Is Vendored

Under `tests/vectors/bip352/official/reference/` the repo now stores the exact upstream Python files needed to run the official reference implementation offline:

- `reference.py`
- `bitcoin_utils.py`
- `bech32m.py`
- `ripemd160.py`
- the minimal `secp256k1lab` source files imported by the reference script
- the upstream `secp256k1lab` license file

The manifest at `tests/vectors/bip352/official/manifest.json` records the source URL and SHA256 for every vendored reference file.

## How It Is Used

`python3 scripts/run_bip352_reference_oracle.py`

or

`make oracle`

The wrapper script:

1. verifies the vendored vector snapshot checksum,
2. verifies every vendored reference-bundle file checksum,
3. runs the exact upstream reference script against the vendored snapshot,
4. writes a machine-readable report to `build/bip352_reference_oracle_report.json`.

## What This Gives Us

- an offline semantic oracle pinned to a specific upstream commit
- proof that the vendored official snapshot still passes the exact upstream reference bundle
- a trustworthy baseline before adapting worker outputs into official send/receive comparisons

The repo now builds on that baseline with:

- a full derived v2 case corpus under `tests/vectors/bip352/derived/v2/`
- a semantic adapter request contract in `../spec/SEMANTIC_ADAPTER.md`
- a normalized semantic comparison contract in `../spec/SEMANTIC_CONTRACT.md`
- a v2 oracle runner that re-derives semantics from those case bytes and compares them to the normalized expectations
- in-tree reference and SPDK-backed semantic adapters that are compared against those expectations
- a compiled semantic worker ABI in `../ffi/sp_differ_semantic.h`
- an SPDK-backed semantic worker shared library that is compared against those expectations

## What It Does Not Solve Yet

- It does not make the original v1 compiled runner execute full receiving vectors.
- It does not compare the original v1 worker ABI directly to the reference oracle on full v2 cases.
- It does not replace the need for a second independent semantic worker implementation.

Those are still important milestones. The oracle, semantic contract, semantic adapter path, and semantic worker ABI are the new baseline, not the end state.
