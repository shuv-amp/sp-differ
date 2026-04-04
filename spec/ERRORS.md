# Error Codes

This document defines the error codes emitted by workers. The codes are strict and stable across implementations.

| Code | Value (u8) | Meaning |
| --- | --- | --- |
| ok | 0x00 | Successful derivation. |
| invalid_input | 0x01 | Input parsing or validation failed. |
| point_at_infinity | 0x02 | Public key aggregation resulted in infinity. |
| zero_scalar | 0x03 | Aggregate scalar reduced to zero. |
| invalid_pubkey | 0x04 | Invalid or non-canonical public key. |
| tweak_out_of_range | 0x05 | Tagged hash interpreted as a scalar is invalid. |
| internal | 0xFF | Unexpected failure in the worker. |

The output `status` byte uses the numeric values defined in `../ffi/sp_differ.h`. See `../docs/ERROR_MAPPING.md` for the stable mapping table.

## Canonical Exit Codes

| Code | Exit Status | Meaning |
|---|---|---|
| MATCH | 0 | Both workers produced identical canonical outputs |
| VALID_MISMATCH | 1 | Both workers completed; outputs differ — this is a divergence |
| BOTH_CRASH | 2 | Both workers returned non-zero exit; likely malformed input |
| WORKER_A_CRASH | 3 | Worker A returned non-zero exit before producing output |
| WORKER_B_CRASH | 4 | Worker B returned non-zero exit before producing output |
| WORKER_A_EMPTY | 5 | Worker A exited 0 but produced empty canonical output |
| WORKER_B_EMPTY | 6 | Worker B exited 0 but produced empty canonical output |
| NORMALIZATION_FAIL | 7 | Input failed normalization; not sent to workers |
| TIMEOUT | 8 | Worker exceeded execution time limit |
| BOTH_ORACLE_MISMATCH | 9 | Both v2 semantic workers completed and agreed, but the shared semantic result failed the vendored expectation |

## Critical Invariant

VALID_MISMATCH (1) MUST only be emitted when BOTH workers completed AND both
produced non-empty outputs AND those outputs differ.
A crash MUST NEVER be reported as VALID_MISMATCH.
An empty output MUST NEVER be reported as MATCH.
These two rules are the entire point of the error taxonomy.

For v2 semantic comparison, `MATCH` means both workers landed in the same
expectation-aware semantic equivalence class. Distinct sender output subsets
that are both accepted by the vendored expectation, or count-only receive
cases where one worker supplies extra detail, MUST NOT be reported as
`VALID_MISMATCH`.
