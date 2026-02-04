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

The output `status` byte uses the numeric values defined in `ffi/sp_differ.h`. See `docs/ERROR_MAPPING.md` for the stable mapping table.
