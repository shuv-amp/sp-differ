# Case Format v2

This document defines SP-DIFFER case format v2. It extends the v1 case model so the harness can represent the official BIP 352 receiving vectors and the sender-side cases that need richer input context.

The current repository executes v2 cases through the compiled runner, compare binary, and CLI by routing them into the semantic bridge and semantic worker ABI.

## Why v2 Exists

The pinned March 28, 2026 official BIP 352 snapshot includes requirements that do not fit the v1 case shape:

- `P2PKH` inputs are common.
- Some sending cases target more than one `(scan_pubkey, spend_pubkey)` recipient group.
- Receiving cases provide outputs to scan, not just a receiver key pair.
- Receiving cases require receiver scan/spend private keys.
- Input pubkey extraction depends on raw `scriptSig`, `txinwitness`, and previous-output `scriptPubKey`.

The local audit tooling in `../scripts/bip352_vectors.py` is the source of truth for those gaps.

## Encoding Rules

- All integers are little-endian.
- Fixed-size byte arrays are raw bytes.
- Variable-length byte fields are encoded as `u16 length` followed by raw bytes.
- Unknown versions, flags, or input types are invalid.

## Case Header

| Field | Type | Notes |
| --- | --- | --- |
| version | u8 | Format version. Current value is `2`. |
| seed | u64 | Deterministic seed for reproduction. |
| flags | u32 | Bit flags describing which optional sections are present. |
| input_count | u16 | Number of inputs. |
| recipient_group_count | u16 | Number of recipient groups. |
| scan_output_count | u16 | Number of outputs-to-scan entries. |
| label_count | u16 | Number of labels. |

## Input Entry

Each input begins with the common fields below, followed by optional sections controlled by flags.

| Field | Type | Notes |
| --- | --- | --- |
| outpoint_txid | [32] | Serialized txid bytes. |
| outpoint_vout | u32 | Output index. |
| input_type | u8 | Enum for input type. |
| prevout_script_pubkey | `u16 + bytes` or empty | Present when flag bit 3 is set. |
| script_sig | `u16 + bytes` or empty | Present when flag bit 4 is set. |
| txinwitness | `u16 + bytes` or empty | Present when flag bit 5 is set. |
| privkey | [32] or empty | Present when flag bit 1 is set. |
| pubkey | [33] or empty | Present when flag bit 2 is set. |

### Input Types (u8)

| Value | Meaning |
| --- | --- |
| 0x01 | P2WPKH |
| 0x02 | P2TR keypath |
| 0x03 | P2SH-P2WPKH |
| 0x04 | P2PKH |

Implementations must reject unknown values.

## Recipient Group Section

When flag bit 6 is set, the case includes `recipient_group_count` entries in the following form:

| Field | Type | Notes |
| --- | --- | --- |
| scan_pubkey | [33] | Compressed receiver scan public key. |
| spend_pubkey | [33] | Compressed receiver spend public key. |
| count | u16 | Number of outputs requested for that group. Must be nonzero. |

## Outputs-To-Scan Section

When flag bit 7 is set, the case includes `scan_output_count` entries:

| Field | Type | Notes |
| --- | --- | --- |
| output_pubkey_xonly | [32] | X-only output key to scan. |

## Receiver Key Material Section

When flag bit 8 is set, the case includes:

| Field | Type | Notes |
| --- | --- | --- |
| scan_privkey | [32] | Receiver scan private key. |
| spend_privkey | [32] | Receiver spend private key. |

The `labels` array follows the receiver key material and contains `label_count` little-endian `u32` values.

## Flags (u32)

| Bit | Meaning |
| --- | --- |
| 0 | Negative test case. |
| 1 | Private keys present for all inputs. |
| 2 | Public keys present for all inputs. |
| 3 | Previous-output `scriptPubKey` present for all inputs. |
| 4 | `scriptSig` present for all inputs. |
| 5 | `txinwitness` present for all inputs. |
| 6 | Recipient group section present. |
| 7 | Outputs-to-scan section present. |
| 8 | Receiver key material section present. |

## Validation Rules

- If flag bit 6 is clear, `recipient_group_count` must be zero.
- If flag bit 7 is clear, `scan_output_count` must be zero.
- If flag bit 8 is clear, `label_count` must be zero.
- Receiver and recipient public keys must use compressed SEC encoding.
- Recipient-group `count` values must be nonzero.
- Missing sections must not be inferred from defaults.

## Compatibility Notes

- v1 remains the original byte-worker ABI format used by the compiled C++ and Rust byte-worker surfaces.
- v2 is the bridge format used for official-vector send/receive execution through the semantic path.
- Output format v1 is unchanged by this document.
