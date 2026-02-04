# C++ Worker

This folder will contain the C++ adapter around libsecp256k1 or Bitcoin Core's Silent Payments implementation. It exposes a stable C ABI to the core runner.

Planned responsibilities:
- Parse the canonical case format.
- Call the implementation under test.
- Serialize outputs using the shared schema.
- Return explicit error codes on invalid inputs.

Current stub:
- `sp_differ_worker.cpp` validates the v1 case format and returns an empty `ok` payload. It is for interface validation only.
