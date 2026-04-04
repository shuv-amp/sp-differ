# Worker Interface

This document describes the C ABI contract implemented by each worker. The authoritative definition is `../ffi/sp_differ.h`.

## Contract Summary

A worker exposes three symbols:

- `sp_differ_worker_api_version()`
- `sp_differ_worker_run(const uint8_t* input, size_t input_len, uint8_t** output, size_t* output_len)`
- `sp_differ_worker_free(uint8_t* output)`

## Behavior

- The worker accepts a case payload defined in `../spec/FORMAT.md`.
- The worker returns a serialized output payload defined in `../spec/FORMAT.md`.
- Output `status` values use the mapping defined in `./ERROR_MAPPING.md`.

## Memory Ownership

- The worker allocates the output buffer.
- The caller must release it via `sp_differ_worker_free`.
- The worker must tolerate being called with empty or malformed inputs and return a clean error.

## Versioning

- The worker ABI version is defined by `SP_DIFFER_WORKER_API_VERSION`.
- Runners must reject workers that return a mismatched ABI version.
