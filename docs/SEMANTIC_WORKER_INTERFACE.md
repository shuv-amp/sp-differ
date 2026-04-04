# Semantic Worker Interface

This document describes the compiled semantic worker ABI. The authoritative definition is [sp_differ_semantic.h](../ffi/sp_differ_semantic.h).

## Why This Exists

The original worker ABI in `../ffi/sp_differ.h` is intentionally small and tied to the v1 binary case/output payloads.

The semantic execution path is richer:

- request payloads follow `../spec/SEMANTIC_ADAPTER.md`
- response payloads follow `../spec/SEMANTIC_CONTRACT.md`
- current real implementations already produce their most complete output at that semantic layer

Freezing that into the old v1 ABI would blur two different concerns. The semantic worker ABI keeps the existing v1 byte-worker ABI stable while providing a compiled boundary for the full v2 semantic corpus.

## Contract Summary

A semantic worker exposes three symbols:

- `sp_differ_semantic_worker_api_version()`
- `sp_differ_semantic_worker_run(const uint8_t* input, size_t input_len, uint8_t** output, size_t* output_len)`
- `sp_differ_semantic_worker_free(uint8_t* output)`

## Behavior

- The worker accepts UTF-8 JSON bytes following `../spec/SEMANTIC_ADAPTER.md`.
- The worker returns UTF-8 JSON bytes following `../spec/SEMANTIC_CONTRACT.md`.
- The worker should return a nonzero status on malformed input or internal execution failure.
- A zero return code means the JSON response is well-formed and ready for semantic comparison.
- The compiled comparator treats expectation-approved alternatives as equivalent in v2 mode, so multiple accepted sender output sets or count-only receive detail differences do not become false `VALID_MISMATCH` reports.
- When two semantic workers return the same normalized result and both still fail the vendored expectation, the comparator reports `BOTH_ORACLE_MISMATCH` rather than a fake crash.

## Memory Ownership

- The worker allocates the response buffer.
- The caller must release it via `sp_differ_semantic_worker_free`.
- The worker must tolerate malformed requests without crashing.

## Versioning

- The semantic worker ABI version is defined by `SP_DIFFER_SEMANTIC_WORKER_API_VERSION`.
- Runners must reject workers that return a mismatched ABI version.

## Current State

- The semantic adapter runner can execute either command-based adapters or semantic worker shared libraries.
- The compiled `sp_differ_runner` and `sp_differ_compare` binaries now also dispatch v2 cases through this ABI via the native C++ semantic bridge, while preserving the original v1 byte-worker path.
- The in-tree Rust SPDK adapter now exposes both forms.
- The in-tree `silent-payments` adapter also exposes both forms and now passes the full official 55-case semantic corpus after fixing a wrapper bug around smallest-outpoint preservation.
- The external Go-backed `go-bip352` adapter also exposes both forms and now passes the full official 55-case semantic corpus after aligning the count-only `K_max` receive case with the normalized semantic contract.
- `make adapter-spdk-ffi` validates the compiled semantic worker path against all 55 derived official v2 cases.
- The compiled v1 worker ABI remains separate and unchanged, but the compiled runner/compare front door is no longer limited to v1 cases.
