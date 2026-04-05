# Testing Strategy

SP-DIFFER uses multiple oracles to reduce false positives and produce actionable reports.

## Oracles

### Differential Oracle

Compares outputs from independent implementations byte-for-byte. Any mismatch is reported with a minimal reproduction case.

### Spec Oracle

Validates outputs against BIP 352 rules such as valid taproot outputs, valid scalars, and valid points on the curve.

The repo now vendors the upstream BIP 352 reference implementation snapshot and can run it offline against the pinned official vectors. That vendored upstream oracle is the current semantic baseline used by this repository.

On top of that oracle, the repo now defines a normalized semantic comparison contract for sender and receiver expectations. That contract is paired with a semantic adapter request contract so real implementations can be driven against the official v2 corpus without each one re-implementing the repository's binary case format.

### Validation Helpers

The repo also ships parser, validator, and semantic comparison helpers that check case/output structure and normalized semantic results.

## Test Types

- Official vectors for baseline correctness.
- Deterministic edge cases for boundary conditions.
- Fuzzed cases generated from seeds and mutated corpora.
- Regression cases derived from real mismatches.

## Reproducibility

Seeded workflows record seeds, input cases, and worker versions. Replayable artifacts are written for semantic adapter failures, fuzz failures, and packaged release checks.

## Local Smoke Tests

- `make check` runs core I/O, case parser, and header validation smoke tests.
- `make check-claims` verifies that public docs and templates avoid unsupported hype and unsupported future-tense release wording.
- `make check-comments` verifies that repo-owned source comments avoid deferred-note markers and hype wording.
- `make sanitize-smoke SANITIZE_CXX=clang++` runs the C++ core, runner, compare, and semantic smoke surfaces under `asan`/`ubsan` in an isolated build directory.
- `make cli-smoke` exercises the public CLI release-readiness aggregator against a synthetic build tree.
- `make release-report` writes a combined release-readiness summary from the current local evidence.
- `make smoke` runs the compiled runner against the canonical example case.
- `make smoke-rust` runs the compiled runner against the Rust byte-worker library.
- `make semantic-smoke` runs the compiled runner and compare binaries against synthetic semantic worker fixtures for send and receive v2 cases, expectation-approved alternative sender outputs, and the explicit `BOTH_ORACLE_MISMATCH` path.
- `make compare` builds the differential runner.
- `make diff` runs the differential runner against the C++ and Rust byte-worker libraries.
- `make oracle` verifies the vendored upstream reference bundle and runs it against the pinned official BIP352 snapshot.
- `make vectors-v2` verifies the full derived v2 semantic corpus against the vendored oracle.
- `make adapters` verifies the in-tree semantic adapters against the same derived v2 corpus.
- `make adapter-spdk-ffi` verifies the SPDK-backed semantic worker shared library against the same derived v2 corpus.
- `make adapter-silent-payments` runs a second independent Rust implementation against the same derived v2 corpus.
- `make adapter-silent-payments-ffi` exercises that same implementation through the semantic worker ABI.
- `make adapter-bip352` runs a third independent Rust implementation against the same derived v2 corpus.
- `make adapter-bip352-ffi` exercises that same implementation through the semantic worker ABI.
- `make adapter-go-bip352` runs a fourth independent implementation backed by the public Go `go-bip352` module against the same derived v2 corpus.
- `make adapter-go-bip352-ffi` exercises that same Go implementation through the semantic worker ABI.
- `make adapter-bdk-sp` runs a fifth independent implementation surface backed by `bdk-sp` against the same derived v2 corpus.
- `make regressions` replays the tracked semantic regression suite against all current known-good adapters.
- `make bench-reference` and `make bench-adapters` measure harness-level adapter latency and throughput on the same pinned derived v2 corpus, while still failing the run if semantic correctness breaks.
- `make release-evidence` hashes the materialized readiness and benchmark outputs into an explicit release-evidence manifest.
- `make verify-release-evidence` re-checks that manifest against the current files and can also be paired with `git tag -v` during release review.
- `make maturity-signoff` is the most complete local maturity lane: live readiness, benchmark matrix, refreshed local report, and release-evidence hashing.
- `make fuzz-corpus` verifies the checked-in semantic worker fuzz corpus.
- `make fuzz-minimizer-smoke` exercises the semantic fuzz reducer against synthetic structured and raw failures.
- `make fuzz-semantic-spdk`, `make fuzz-semantic-silent-payments`, `make fuzz-semantic-bip352`, and `make fuzz-semantic-go-bip352` run deterministic semantic-worker fuzzing with replayable and auto-minimized artifacts under `build/`.
- `make fuzz-semantic-workers FUZZ_STRUCTURED_ITERATIONS=64 FUZZ_RAW_ITERATIONS=64` runs the longer deterministic local matrix across all semantic workers.
- `.github/workflows/ci.yml` currently runs the regular Ubuntu `Build, Test, and Smoke` lane on pushes and pull requests targeting `main`.
- `.github/workflows/nightly-fuzz.yml` runs the longer scheduled semantic-worker fuzz jobs and uploads replay bundles as tarred artifacts.
- `.github/workflows/maturity.yml` runs scheduled live release verification, benchmark collection, release-evidence generation, and artifact upload.
- `sp-differ status --profile release --require-green` now provides a single readiness check over the current oracle, adapter, regression, and fuzz evidence, and it also incorporates `build/bip352_external_probe.json` automatically when present so stale or failed integrated external-version evidence is reflected in the status report.
- `make verify-release-live` is the stricter networked sign-off path: it runs the release-profile verification suite and, when external-probe candidate metadata is present, refreshes the live upstream probe before writing `build/sp_differ_release_readiness_live.json`. Without that metadata it still writes the live readiness report and notes that upstream freshness was not evaluated.
- `make vectors` runs the upstream oracle, validates the full derived v2 semantic corpus, checks the generated v1-compatible derived subset, and runs that subset through both byte-worker libraries.

Benchmark summaries are intentionally separate from release-readiness verdicts. They are useful for lab comparison and regression detection, but they should only be compared when the corpus selection, timeout, and iteration signature match exactly.
Release evidence manifests are intentionally separate from both of those reports: they record exactly which files backed a candidate release so later reviewers can hash and verify the same material.

## Official Vector Status

The authoritative upstream BIP352 send-and-receive vectors are vendored under `tests/vectors/bip352/official/` with a pinned manifest. The matching upstream reference bundle is vendored alongside them and checked by SHA256 before oracle execution. A derived sender-side subset that fits the current SP-DIFFER v1 case format lives under `tests/vectors/bip352/derived/v1/`. The full official send/receive surface encoded as SP-DIFFER v2 cases lives under `tests/vectors/bip352/derived/v2/`, and `../spec/SEMANTIC_ADAPTER.md` defines the stable request/response bridge used to drive real implementations against that corpus.

The vendored current semantic corpus is executed through both the semantic adapter layer and the compiled semantic worker ABI. The compiled runner and compare binaries preserve the original v1 byte-worker ABI and also dispatch v2 cases through the semantic bridge and semantic worker ABI. The compare path is expectation-aware: official sender cases with multiple accepted output sets and count-only receive cases do not produce false `VALID_MISMATCH` reports, while shared semantic failures surface as `BOTH_ORACLE_MISMATCH`. The repo also tracks promoted semantic regressions under `tests/regressions/semantic/`; the retained manifest includes the two historical `silent-payments` send mismatches on official cases 19 and 21. The repo also ships a deterministic semantic-worker fuzz corpus, a replayable local fuzz runner for compiled semantic workers, an automatic reducer that shrinks failures before promotion, CI workflows that preserve replay bundles as tarred artifacts, a longer deterministic 64/64 local fuzz matrix across the SPDK, `silent-payments`, `bip352`, and `go-bip352` semantic workers, and the local `sp-differ` readiness/reporting CLI. The canonical release gate also includes the `bdk-sp` semantic adapter and its regression replay surface. See `./CASE_FORMAT_V2.md`, `./SEMANTIC_WORKER_INTERFACE.md`, `../spec/SEMANTIC_ADAPTER.md`, and `../spec/SEMANTIC_CONTRACT.md` for the current state.

## Failure Policy

A mismatch is a failure unless explicitly classified as a serialization or normalization difference that does not change semantics. The classification is recorded in the report, semantic adapter failures can emit replayable per-case artifacts under `build/`, semantic worker fuzz failures now emit reduced replay bundles under `minimized/`, CI packages those outputs as tar archives for upload, and structured bundles can be promoted into the tracked regression suite with `scripts/intake_semantic_regressions.py`.
