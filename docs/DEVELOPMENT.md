# Development Guide

This guide describes the minimal, deterministic workflow used to validate the worker interface and output contract.

## Prerequisites

- C++17 compiler (Apple clang or GCC)
- `make`
- Python 3
- Rust toolchain for the Rust-backed semantic adapters and workers
- Go 1.24+ for the external `go-bip352` adapter and worker

## Quick Start

Build the worker and run the compiled runner against the canonical example case:

```bash
make smoke
```

You should see:

```text
OK: output valid
```

For the public repo-local CLI:

```bash
python3 -m pip install --editable .
sp-differ status --profile release --require-green
```

## Useful Commands

- Build the C++ byte-worker library: `make worker`
- Build the runner: `make runner`
- Build the Rust byte-worker library: `make worker-rust` (output in `build/`)
- Run the Rust worker smoke check: `make smoke-rust`
- Run the converged compiled semantic smoke check: `make semantic-smoke`
- Run the runner against the Rust worker: `build/sp_differ_runner tests/vectors/example.hex --worker rust`
- Build the differential runner: `make compare`
- Run the differential runner: `build/sp_differ_compare tests/vectors/example.hex --left cpp --right rust`
- Run core smoke tests (I/O, case parser, header validation): `make check`
- Run the public claim-discipline gate for docs and templates: `make check-claims`
- Run the source-comment discipline gate for repo-owned code: `make check-comments`
- Run the public CLI smoke test: `make cli-smoke`
- Write a combined release-readiness report from the current `build/` evidence: `make release-report`
- Run the public CLI verification profile without the longer fuzz matrix: `make verify-quick`
- Run the public CLI release profile with the longer fuzz matrix and release report: `make verify-release`
- Run the stricter networked release sign-off that refreshes upstream probe evidence first: `make verify-release-live`
- Run the full maturity lane when you want the closest thing to release-grade local evidence in one command: `make maturity-signoff`
- Re-check the current release-evidence manifest against on-disk files: `make verify-release-evidence`
- Before any public release, read `./RELEASE.md` and make sure the evidence manifest and signed-tag requirements are satisfied.
- Run the sanitizer-backed C++ smoke lane locally before touching runner/compare/core code: `make sanitize-smoke SANITIZE_CXX=clang++`
- Run the pinned upstream BIP352 semantic oracle offline: `make oracle`
- Run the full derived v2 semantic corpus against the vendored oracle: `make vectors-v2`
- Run the in-tree semantic adapters against the full v2 corpus: `make adapters`
- Run the SPDK-backed semantic worker shared library against the full v2 corpus: `make adapter-spdk-ffi`
- Run the second independent `silent-payments` adapter against the full v2 corpus: `make adapter-silent-payments`
- Run the second independent `silent-payments` semantic worker against the full v2 corpus: `make adapter-silent-payments-ffi`
- Run the third independent `bip352` adapter against the full v2 corpus: `make adapter-bip352`
- Run the third independent `bip352` semantic worker against the full v2 corpus: `make adapter-bip352-ffi`
- Run the fourth independent `go-bip352` adapter against the full v2 corpus: `make adapter-go-bip352`
- Run the fourth independent `go-bip352` semantic worker against the full v2 corpus: `make adapter-go-bip352-ffi`
- Run the tracked semantic regression suite against the green adapters: `make regressions`
- Check the semantic worker fuzz corpus: `make fuzz-corpus`
- Exercise the fuzz minimizer in isolation: `make fuzz-minimizer-smoke`
- Run deterministic semantic-worker fuzzing against SPDK: `make fuzz-semantic-spdk`
- Run deterministic semantic-worker fuzzing against `silent-payments`: `make fuzz-semantic-silent-payments`
- Run deterministic semantic-worker fuzzing against `bip352`: `make fuzz-semantic-bip352`
- Run deterministic semantic-worker fuzzing against `go-bip352`: `make fuzz-semantic-go-bip352`
- Run the longer deterministic semantic-worker fuzz matrix across all workers: `make fuzz-semantic-workers FUZZ_STRUCTURED_ITERATIONS=64 FUZZ_RAW_ITERATIONS=64`
- Audit the vendored official BIP352 vectors and run the current derived subset through both byte-worker libraries: `make vectors`
- Parse a case file: `python3 scripts/parse_case.py tests/vectors/example.hex`
- Parse the canonical v2 case file: `python3 scripts/parse_case.py tests/vectors/example_v2.hex`
- Validate an output payload: `python3 scripts/validate_output.py tests/vectors/output_ok.hex`

## Notes

- The runner accepts hex or binary case files.
- The original byte-worker ABI still covers the v1 contract, but the compiled runner/compare binaries also dispatch v2 cases through the semantic bridge and semantic worker ABI.
- `make check` also exercises the Python helper scripts against the canonical v1 and v2 example payloads.
- `make check` now also includes the public claim-discipline gate, so unsupported hype and unsupported future-tense release wording fail locally before review.
- `make check` now also includes the source-comment discipline gate, so repo-owned comments do not accumulate deferred-note markers, hype, or vague certainty wording.
- `make check` now also exercises the public CLI report aggregator against a synthetic build tree.
- `make oracle` verifies the vendored upstream reference bundle checksums and runs the exact upstream BIP352 reference implementation against the pinned official snapshot.
- `make vectors-v2` verifies that the full official send/receive surface projects into case format v2 and that the v2 oracle runner matches the normalized semantic expectations.
- `make adapters` drives the same v2 corpus through the in-tree reference adapter, the SPDK command adapter, the SPDK semantic worker shared library, the independent `silent-payments` implementation in both command and semantic-worker forms, the independent `bip352` implementation in both forms, the external Go-backed `go-bip352` implementation in both forms, and the `bdk-sp` semantic adapter.
- The historical `silent-payments` send mismatch was a wrapper bug: the adapter filtered out ineligible inputs before sender construction, which changed the lexicographically smallest serialized outpoint used by the upstream sender.
- Longer deterministic fuzzing also flushed out two smaller wrapper-level bugs that are now covered by unit tests: send-side `input_hash` must use `a_sum * G` rather than extracted input pubkeys, and the `bip352` receive path must only validate output pubkeys when scanning is actually reached so point-at-infinity short-circuits still match the oracle.
- The `go-bip352` wrapper also needed one normalization-layer fix before it was promoted into the green set: the official count-only `K_max` receive case must stop at `2323` matches even though the upstream library can continue scanning the 2,324th match.
- Semantic adapter runs now produce JSON reports, markdown summaries, and replayable per-failure artifacts under `build/`; adapter fuzz artifacts now also carry exact-request replay commands instead of only a broad seed rerun.
- Failure artifact directories now include a one-command promotion path into `tests/regressions/semantic/`, and `make regressions` replays tracked cases with the same semantic compare engine.
- The repo now also has a deterministic semantic-worker fuzz corpus under `fuzz/corpus/semantic_worker/` plus a replayable fuzz runner that cross-checks structured valid mutations against the vendored reference path and throws malformed raw payloads at the semantic worker ABI.
- Semantic worker fuzz failures are now auto-minimized before they are written under `build/`: the reducer keeps the same failure signature, saves a reduced replay input under `minimized/`, and emits a promotable regression bundle for structured failures that still round-trip into case format v2.
- Structured fuzz mutations now use valid secp256k1 pubkeys and secret scalars for the fields they randomize, which keeps the long deterministic fuzz lane focused on semantic behavior instead of off-curve junk.
- `sp_differ_cli.py` is the public repo-local entrypoint: it wraps canonical verification profiles, writes release-readiness summaries, and can replay saved failure artifacts without making users remember the individual helper scripts.
- `sp_differ_cli.py verify --refresh-external-probe` is the networked sign-off variant: when external-probe candidate metadata is present, it reruns the external BIP352 probe before producing the final release verdict. Without that metadata it still produces the live readiness report and notes that upstream freshness was not evaluated.
- When `build/bip352_external_probe.json` exists, the same CLI status/report path also folds in the live integrated-adapter freshness probe and marks the report failed or incomplete on stale, failed, or partial external evidence.
- The CLI packaging path is verified through `python3 -m pip install --editable .`, and the installed `sp-differ` console entrypoint now works against the current repo checkout.
- `.github/workflows/ci.yml` currently runs the regular Ubuntu `Build, Test, and Smoke` lane on pushes and pull requests targeting `main`.
- `.github/workflows/nightly-fuzz.yml` carries the longer scheduled semantic-worker fuzz jobs, while `.github/workflows/maturity.yml` carries scheduled live release verification, benchmark runs, and release-evidence artifact generation.
- `scripts/package_ci_artifacts.py` now tars CI outputs before upload so replay scripts keep their permissions and the workflow artifacts preserve the original directory layout.
- `make vectors` runs the upstream oracle, validates the full derived v2 semantic corpus, checks the derived v1-compatible subset, and runs that v1 subset through both byte-worker libraries.
- The original compiled worker ABI is still v1-only, but the compiled runner/compare surface is no longer: v2 sender/receiver execution now also exists through `../spec/SEMANTIC_ADAPTER.md`, `../ffi/sp_differ_semantic.h`, the semantic bridge helper, and the in-tree semantic adapters/workers.
- Build artifacts are placed in `build/`.
