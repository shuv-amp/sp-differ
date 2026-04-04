# Changelog

This file documents notable project changes.

## Unreleased

- Initial project structure and documentation.
- Vendored the official BIP352 vector snapshot with a pinned manifest and added audit/projection tooling.
- Added draft case format v2 docs, parsing scaffolding, and a canonical v2 example fixture.
- Vendored the exact upstream BIP352 reference bundle, added an offline semantic oracle target, and recorded per-file provenance/checksums in the official manifest.
- Added a normalized semantic comparison contract, generated the full official v2 case corpus with expectation sidecars, and added a v2 oracle runner that re-derives and compares sender/receiver semantics from case bytes.
- Added a semantic adapter request contract, a generic v2 adapter runner, an in-tree reference adapter, and a real SPDK-backed Rust adapter for full official-vector semantic execution.
- Extended semantic adapter runs with markdown summaries, optional single-case replay, and per-failure artifact bundles.
- Added a compiled semantic worker ABI, a ctypes-based shared-library bridge, and an SPDK-backed Rust semantic worker that passes the full official v2 corpus.
- Added a second independent Rust adapter backed by the public `silent-payments` crate, exposed as both a command adapter and a semantic worker.
- Added a third independent Rust adapter backed by the public `bip352` crate, exposed as both a command adapter and a semantic worker.
- Added a fourth independent adapter backed by the public Go `go-bip352` module, exposed as both a command adapter and a semantic worker.
- Added a first-class semantic regression intake and replay workflow under `tests/regressions/semantic/`.
- Root-caused and fixed the `silent-payments` send mismatch on official cases 19 and 21 by preserving the full transaction input set during upstream sender construction, added targeted regression tests for that wrapper bug, and cleared the active semantic regression manifest.
- Added a deterministic semantic-worker fuzz corpus, a semantic request mutation dictionary, and a replayable local fuzz runner for compiled semantic workers.
- Added automatic semantic fuzz failure minimization, promotable reduced regression bundles, CI artifact tar packaging, short deterministic semantic-worker fuzzing in regular CI, and a separate nightly semantic fuzz workflow with artifact upload.
- Hardened the semantic worker fuzz mutators so randomized key fields stay on-curve and use valid secret scalars, which keeps the deterministic structured lane focused on semantic behavior.
- Root-caused and fixed two later fuzz-found wrapper issues: send-side `input_hash` must use `a_sum * G` rather than extracted input pubkeys, and the `bip352` receive wrapper must only validate malformed output pubkeys when scanning is actually reached so point-at-infinity short-circuits still match the oracle.
- Verified a green longer local deterministic fuzz matrix at `FUZZ_STRUCTURED_ITERATIONS=64` and `FUZZ_RAW_ITERATIONS=64` across the SPDK, `silent-payments`, `bip352`, and `go-bip352` semantic workers.
- Added a local `sp-differ` CLI with `verify`, `status`, and `replay`. `verify` runs verification profiles, `status` summarizes current `build/` evidence, and `replay` reruns saved failure artifacts. Also added editable-install packaging via `pyproject.toml` and CLI smoke coverage in `make check`.
- Converged the compiled runner/compare front door so v1 cases still use the original byte-worker ABI while v2 cases are bridged into the semantic worker path, and added `make semantic-smoke` coverage for that compiled v2 dispatch.
- Added harness-level semantic benchmark reporting, comparison-safe summaries, and scheduled maturity evidence packaging.
- Added live external-version freshness probing, a networked release verification lane, and hashed release-evidence manifests.
- Added independent release-evidence verification so published manifests can be rechecked against current files before release.
- Added sanitizer-backed smoke coverage, Linux+macOS CI coverage, a Python-version CI matrix, and scheduled maturity/nightly-fuzz workflows with pinned Python setup.
- Added repo-local claim-discipline checks so public docs and review templates stay evidence-backed and avoid unsupported future-tense release language.

### Known Issues

- The `spdk-rust` external probe can report a version freshness failure in the CLI status command when a local probe file is present and marks that adapter stale. When no local probe file is present, the CLI reports that upstream freshness was not evaluated. This affects upstream version tracking only and does not affect harness correctness or case results.
