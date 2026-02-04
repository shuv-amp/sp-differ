# Case Format v1

The canonical case format is a compact, versioned, length-delimited binary encoding. This document defines the fields and their semantics.

## Case Header

| Field | Type | Notes |
| --- | --- | --- |
| version | u8 | Format version. Current value is 1. |
| seed | u64 | Deterministic seed for reproduction. |
| flags | u32 | Bit flags describing case properties. |
| input_count | u16 | Number of inputs. |
| output_count | u16 | Number of output keys to derive. |

## Input Entry

| Field | Type | Notes |
| --- | --- | --- |
| outpoint_txid | [32] | Transaction id bytes. |
| outpoint_vout | u32 | Output index, little-endian. |
| input_type | u8 | Enum for input type. |
| privkey | [32] or empty | Optional private key. |
| pubkey | [33] or empty | Optional public key. |

## Receiver Fields

| Field | Type | Notes |
| --- | --- | --- |
| scan_pubkey | [33] | Receiver scan public key. |
| spend_pubkey | [33] | Receiver spend public key. |
| labels | u32 * m | Optional labels. |

## Flags

| Bit | Meaning |
| --- | --- |
| 0 | Negative test case. |
| 1 | Private keys present. |
| 2 | Public keys present. |

## Notes

- Inputs may include private keys, public keys, or both.
- If both are present, the public key must match the private key.
- Encoding details such as length prefixes are defined in the worker interface and must be identical across implementations.
