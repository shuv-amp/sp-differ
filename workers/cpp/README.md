# C++ Worker

This folder contains the native C++ implementation of the original `ffi/sp_differ.h` byte-worker ABI.

Current responsibilities:
- Parse SP-DIFFER case format v1.
- Derive sender outputs for the published byte-worker contract with `libsecp256k1`.
- Serialize output pubkeys and tweaks into the shared v1 payload.
- Return explicit status codes on malformed inputs and edge cases.

Current implementation:
- `sp_differ_worker.cpp` computes the v1 byte-worker sender result for supported inputs and returns the serialized output payload consumed by the compiled runner.
