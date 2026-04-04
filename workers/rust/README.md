# Rust Worker

This folder contains the Rust implementation of the original `ffi/sp_differ.h` byte-worker ABI.

Current responsibilities:
- Parse the published v1 byte-worker input surface.
- Return deterministic status bytes through the byte-worker ABI.
- Provide cross-language contract coverage for the original byte-worker surface.

Current implementation:
- `src/lib.rs` validates the v1 byte-worker input surface and returns the minimal status payload used for cross-language contract checks.

Build output:
- `make worker-rust` produces `build/libsp_differ_worker_rust.*` (platform-specific extension).
- `make smoke-rust` runs the compiled runner against the Rust byte-worker library.
