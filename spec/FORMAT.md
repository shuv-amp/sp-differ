# Case Format v1

This document defines the canonical input and output formats used by SP-DIFFER. The format is compact, binary, and versioned. It is intentionally strict to prevent ambiguity across implementations.

## Design Goals

- Deterministic and replayable by seed.
- Minimal encoding complexity and no hidden defaults.
- Explicit versioning and forward-compatible extension points.

## Encoding Rules

- All integers are little-endian.
- Fixed-size byte arrays are raw bytes (no hex or base encoding).
- Variable-length sections are length-prefixed with `u16`.
- Unknown versions or unknown enums are invalid input.

## Case Header

| Field | Type | Notes |
| --- | --- | --- |
| version | u8 | Format version. Current value is `1`. |
| seed | u64 | Deterministic seed for reproduction. |
| flags | u32 | Bit flags describing case properties. |
| input_count | u16 | Number of inputs. |
| output_count | u16 | Number of output keys to derive. |

## Input Entry

| Field | Type | Notes |
| --- | --- | --- |
| outpoint_txid | [32] | Transaction id bytes. |
| outpoint_vout | u32 | Output index. |
| input_type | u8 | Enum for input type. |
| privkey | [32] or empty | Optional private key. |
| pubkey | [33] or empty | Optional public key. |

### Input Types (u8)

| Value | Meaning |
| --- | --- |
| 0x01 | P2WPKH |
| 0x02 | P2TR keypath |
| 0x03 | P2SH-P2WPKH |
| 0xFF | Reserved (invalid) |

Implementations must reject unknown values.

## Receiver Fields

| Field | Type | Notes |
| --- | --- | --- |
| scan_pubkey | [33] | Receiver scan public key. |
| spend_pubkey | [33] | Receiver spend public key. |
| label_count | u16 | Number of labels. |
| labels | u32 * m | Optional labels in provided order. |

## Flags (u32)

| Bit | Meaning |
| --- | --- |
| 0 | Negative test case (expected to fail). |
| 1 | Private keys present for all inputs. |
| 2 | Public keys present for all inputs. |

If both private and public keys are present, public keys must match the derived public keys from private keys. Mismatches are invalid input.

## Output Format v1

Workers return a single serialized result with explicit status and a deterministic ordering.

### Output Header

| Field | Type | Notes |
| --- | --- | --- |
| version | u8 | Output format version. Current value is `1`. |
| status | u8 | Error code mapped from `spec/ERRORS.md`. |
| output_count | u16 | Number of output keys in the payload. |

### Output Payload (when `status = ok`)

| Field | Type | Notes |
| --- | --- | --- |
| output_pubkeys | [33] * k | Derived recipient keys. |
| tweaks | [32] * k | Tweak scalars, for debugging and diffing. |

### Output Payload (when `status != ok`)

No payload bytes are returned. The status code is the only output.

## Compatibility Notes

- Any change to field ordering or sizes requires a new format version.
- The runner will reject cases with unknown versions or unsupported flags.
- Implementations must not interpret missing fields as defaults.
