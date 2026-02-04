# Canonical Example Case (v1)

This example is a single, valid test case encoded with the v1 case format. It is intentionally small and deterministic so it can be used as a reference for parsers and workers.

## Summary

- `version`: `1`
- `seed`: `0x42`
- `flags`: `0x00000002` (private keys present)
- `input_count`: `1`
- `output_count`: `1`
- `input_type`: `0x01` (P2WPKH)
- `labels`: none

Receiver keys:
- `scan_pubkey`: generator point `G` (compressed)
- `spend_pubkey`: `2G` (compressed)

## Layout Order

The binary payload is encoded in this exact order:

1. Case header
2. `input_count` input entries
3. Receiver fields

## Example Values

Input 0:
- `outpoint_txid`: `00 01 02 ... 1f`
- `outpoint_vout`: `0`
- `input_type`: `0x01`
- `privkey`: `0x0000000000000000000000000000000000000000000000000000000000000001`

Receiver fields:
- `scan_pubkey`: `02 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798`
- `spend_pubkey`: `02 c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5`
- `label_count`: `0`

## Hex Encoding

The file `tests/vectors/example.hex` contains the raw hex-encoded payload below.

```text
0142000000000000000200000001000100000102030405060708090a0b0c0d0e0f
101112131415161718191a1b1c1d1e1f0000000001000000000000000000000000
000000000000000000000000000000000000010279be667ef9dcbbac55a06295ce
870b07029bfcdb2dce28d959f2815b16f8179802c6047f9441ed7d6d3045406e95c
07cd85c778e4b8cef3ca7abac09b95c709ee50000
```
