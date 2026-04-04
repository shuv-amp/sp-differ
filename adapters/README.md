# Semantic Adapters

This directory contains implementation-facing semantic adapters.

These adapters are not the same as the current compiled v1 worker ABI under `workers/`.

Instead, they:

1. consume the JSON request defined in `spec/SEMANTIC_ADAPTER.md`,
2. execute sender or receiver logic using a real implementation surface,
3. emit a normalized result matching `spec/SEMANTIC_CONTRACT.md`.

Current adapters:

- `reference/semantic_adapter.py`: wrapper around the vendored upstream BIP352 reference bundle
- `spdk_rust/`: Rust adapter backed by the public `silentpayments` crate, exposed both as a command adapter and as a semantic worker shared library
- `silent_payments_rust/`: second independent Rust adapter backed by the public `silent-payments` crate, exposed both as a command adapter and as a semantic worker shared library
- `bip352_rust/`: third independent Rust adapter backed by the public `bip352` crate, exposed both as a command adapter and as a semantic worker shared library
- `go_bip352/`: fourth independent adapter backed by the public Go `go-bip352` module, exposed both as a command adapter and as a semantic worker shared library
- `bdk_sp_rust/`: optional Rust adapter backed by the public `bdk_sp` crate from the BDK workspace, exposed as a command adapter for semantic corpus and regression runs

The generic runner is `python3 scripts/run_semantic_adapter_cases.py`.
