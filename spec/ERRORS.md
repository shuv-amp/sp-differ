# Error Codes

This document defines the error codes emitted by workers. The codes are strict and stable across implementations.

| Code | Meaning |
| --- | --- |
| ok | Successful derivation. |
| invalid_input | Input parsing or validation failed. |
| point_at_infinity | Public key aggregation resulted in infinity. |
| zero_scalar | Aggregate scalar reduced to zero. |
| invalid_pubkey | Invalid or non-canonical public key. |
| tweak_out_of_range | Tagged hash interpreted as a scalar is invalid. |
| internal | Unexpected failure in the worker. |
