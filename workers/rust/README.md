# Rust Worker

This folder will contain the Rust adapter around a Silent Payments implementation such as rust-silentpayments or bdk-sp. It exposes a stable C ABI to the core runner.

Planned responsibilities:
- Parse the canonical case format.
- Call the implementation under test.
- Serialize outputs using the shared schema.
- Return explicit error codes on invalid inputs.
