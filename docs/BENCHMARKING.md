# Benchmarking

SP-DIFFER includes a benchmark lane so performance results use the same pinned corpus and reporting rules as the rest of the harness.

## Why This Exists

As of April 1, 2026, the closest public BIP352 implementation repos that SP-DIFFER already tracks and integrates do not appear to expose a comparable first-class benchmark surface in their current public trees:

- `cygnet3/rust-silentpayments`
- `setavenger/go-bip352`
- `bitcoindevkit/bdk-sp`

By contrast, Bitcoin Core carries an explicit `src/bench/` tree and libsecp256k1 carries dedicated benchmark sources in `src/bench.c`, `src/bench_ecmult.c`, and `src/bench_internal.c`.

That means benchmarking belongs here, but only if it is measured honestly and on a normalized corpus.

## What SP-DIFFER Measures

The semantic benchmark lane runs implementations through the same derived BIP352 v2 corpus and semantic contract already used for correctness checks.

Per report it records:

- adapter invocation throughput and latency
- end-to-end harness throughput and latency
- contract-validation overhead split from adapter execution
- send/receive breakdowns
- slowest cases on the selected corpus

Each benchmark run still checks correctness. A run that mismatches the semantic expectation is reported as failed instead of producing a misleading timing summary.

## What These Numbers Mean

- Command-adapter numbers include process startup and JSON bridge overhead.
- Worker-library numbers include the `semantic_worker_ffi.py` bridge overhead.
- These are harness measurements, not universal claims about raw upstream library speed.
- Reports are only directly comparable when their `comparison_signature` matches.

The summary script enforces that rule so mixed corpus selections or iteration counts do not get ranked together by accident.

## How To Run

Quick local sample:

```bash
make bench-reference BENCH_MAX_CASES=8 BENCH_ITERATIONS=2 BENCH_WARMUP=0
```

Full current adapter matrix:

```bash
make bench-adapters BENCH_ITERATIONS=3 BENCH_WARMUP=1
```

Outputs:

- per-adapter benchmark JSON and Markdown reports under `build/`
- aggregated benchmark JSON and Markdown summaries under `build/`

## How To Use The Results

Use wording such as:

- "fastest in this SP-DIFFER harness run"
- "measured on the pinned derived v2 corpus"
- "not directly comparable to wallet-level or networked workloads"

Avoid wording such as:

- "fastest everywhere"
- "top implementation everywhere"
- "production-performance guarantee"

## Operational Notes

For reviewer-grade measurements, prefer a quiet dedicated machine, pin toolchain versions, and rerun the same matrix more than once. Shared CI runners are useful for smoke coverage of the benchmark tooling itself, but they are not the right place to make strong absolute performance claims.
