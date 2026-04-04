# Error Mapping

This document defines the stable mapping between worker status codes and the output `status` byte.

The output `status` byte is the numeric value of the `sp_differ_status` enum defined in `../ffi/sp_differ.h`.

| Status Byte | Name | Meaning |
| --- | --- | --- |
| 0x00 | ok | Successful derivation. |
| 0x01 | invalid_input | Input parsing or validation failed. |
| 0x02 | point_at_infinity | Public key aggregation resulted in infinity. |
| 0x03 | zero_scalar | Aggregate scalar reduced to zero. |
| 0x04 | invalid_pubkey | Invalid or non-canonical public key. |
| 0x05 | tweak_out_of_range | Tagged hash interpreted as a scalar is invalid. |
| 0xFF | internal | Unexpected failure in the worker. |

## Canonical Source

The canonical comparator/runner exit taxonomy is defined in `../spec/ERRORS.md`.
Use that document as the source of truth for cross-worker comparison outcomes.

## Error Consequences

- VALID_MISMATCH: Real divergence. Reproduce and file. This is a bug in one
	implementation.
- BOTH_CRASH: Probably malformed input. Check normalization. Not a divergence.
- BOTH_ORACLE_MISMATCH: Both semantic workers agreed on the same result, but that
	result still failed the vendored expectation. This is an oracle/spec failure,
	not a crash.
- WORKER_*_CRASH: One implementation has a crash bug. File against that worker.
- NORMALIZATION_FAIL: Input rejected before workers ran. Not a divergence.
- TIMEOUT: Infrastructure issue or pathological input. Not a divergence.
