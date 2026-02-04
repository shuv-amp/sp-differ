# Rust Worker

This folder will contain the Rust adapter around a Silent Payments implementation such as rust-silentpayments or bdk-sp. It exposes a stable C ABI to the core runner.

Planned responsibilities:
- Parse the canonical case format.
- Call the implementation under test.
- Serialize outputs using the shared schema.
- Return explicit error codes on invalid inputs.

Current stub:
- `src/lib.rs` validates the case header and returns an empty `ok` payload. It is for interface validation only.

Build output:
- `make worker-rust` produces `build/libsp_differ_worker_rust.*` (platform-specific extension).
- `make smoke-rust` runs the compiled runner against the Rust stub.
