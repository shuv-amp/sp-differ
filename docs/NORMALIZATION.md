# Normalization Rules

Status note:

- Rules 1 through 9 are current rules used by the case formats, validation logic, or current semantic execution path.
- "ECDH Point Serialization" and "Label Handling" describe current protocol rules used by the semantic path.
- "SegWit v2+ Transaction Exclusion" is a planned rule. It documents intended behavior, but this file does not assign a comparator exit code for it.
- Historical placeholder headings were removed from this document.

These rules are the contract across implementations. Any worker that does not follow them is considered incorrect for differential comparison.

1. Canonicalized harness cases may serialize inputs in deterministic outpoint order (`txid` bytes, then `vout` as little-endian bytes) so generated artifacts are stable.
2. BIP 352 `input_hash` uses the single lexicographically smallest serialized outpoint together with the aggregated input public key. Workers must not hash the entire sorted outpoint list.
3. Public keys are normalized to compressed 33-byte secp256k1 format.
4. Taproot public keys follow BIP 341 even-Y rules. If the Y coordinate is odd, the key is negated.
5. Aggregate private keys are reduced modulo curve order `n` and rejected if the result is zero.
6. Aggregate public keys are rejected if the sum is the point at infinity.
7. Tagged hash outputs interpreted as scalars are rejected if zero or greater than or equal to `n`.
8. Input types must be explicit and known. Unknown types are invalid input.
9. Labels are provided in canonical order and used as-is without implicit sorting.

## ECDH Point Serialization

Before hashing the ECDH shared secret, the shared secret point is serialized as a 33-byte compressed SEC1 point:
- 1 byte prefix: 0x02 if Y is even, 0x03 if Y is odd
- 32 bytes: X coordinate, big-endian

The 32-byte x-only representation is not used here. Using x-only serialization before hashing produces a different hash from a BIP 352 implementation that uses the compressed point encoding.

BIP 352 defines `ecdh_shared_secret = input_hash * a * B_scan`, and the result is hashed in compressed form.

An implementation that strips the Y-parity byte before hashing will diverge on cases where the shared-secret point has odd Y.

## Label Handling

Label derivation uses HMAC-SHA256 as a tagged hash:

	t_k = sha256(ser_P(b_scan · G) || ser_32(m))

where:
- ser_P(b_scan · G) is the 33-byte compressed serialization of the scan pubkey
- ser_32(m) is the label value m encoded as a 4-byte big-endian uint32
- m=0 is the "no label" case and MUST be supported
- m >= 1 are named labels

The spend key for label m is:
	B_m = B_spend + t_k · G

In SP-DIFFER case format v2, labels are carried as the `labels` array that follows the receiver key material. In the semantic adapter request, the same values appear as the `labels` array.

Implementations that support labeled receiving should treat `m = 0` the same as the unlabeled case and derive labeled spend keys from each value in that array.

## SegWit v2+ Transaction Exclusion

If a transaction contains any input spending a SegWit version 2 or higher output (scriptPubKey starting with OP_2 through OP_16 followed by a push), the entire transaction is excluded from the scan set.

This is not a per-input exclusion. One SegWit v2+ input disqualifies the whole transaction.

This document does not assign a worker status byte or comparator exit code for that case. If the rule is implemented in the harness, the execution-layer documentation should define how that rejection is reported.

This rule exists because future SegWit versions may introduce key-derivation semantics that are incompatible with BIP 352 scanning.
