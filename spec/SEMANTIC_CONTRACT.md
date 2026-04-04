# Semantic Contract v1

This document defines the normalized semantic comparison contract used for full official BIP 352 sender and receiver comparisons.

This contract is intentionally separate from the worker ABI in `../ffi/sp_differ.h`. It is a normalization layer that command adapters and semantic workers target after decoding or deriving their native outputs.

## Why This Exists

The worker ABI and binary output format are still early and v1-oriented. The official BIP 352 vectors exercise richer semantics:

- sender cases can have multiple valid output sets
- receive cases can be detailed or count-only
- some outcomes are semantic states, not worker failures

The semantic contract provides a stable, versioned shape for comparing:

1. the vendored upstream oracle,
2. future worker adapters,
3. compiled semantic workers,
4. regression artifacts derived from real mismatches.

## Format

The contract is JSON.

Common fields:

| Field | Type | Notes |
| --- | --- | --- |
| `semantic_contract_version` | integer | Current value is `1`. |
| `case_format_version` | integer | Current value is `2`. |
| `kind` | string | `send` or `receive`. |
| `source` | object | Provenance metadata such as official vector indices and upstream commit. |
| `semantic_status` | string | Normalized semantic disposition. |
| `input_pubkeys` | string[] | Compressed pubkeys extracted from inputs, in input order, skipping unusable inputs. |
| `input_hash` | hex string or `null` | The BIP 352 input hash when it exists. |
| `notes` | string[] | Optional comparison notes. Sorted and de-duplicated in canonical form. |

## Semantic Status Values

| Status | Meaning |
| --- | --- |
| `ok` | Semantic execution completed successfully. |
| `no_eligible_inputs` | No valid input pubkeys were extracted, so output derivation/scanning is skipped. |
| `zero_scalar` | Sender private key aggregation reduced to zero. |
| `point_at_infinity` | Receiver public key aggregation resulted in infinity. |
| `recipient_limit_exceeded` | Sender-side per-group recipient count exceeded `K_max`. |
| `invalid_input` | Input parsing/validation failed before semantics could run. |
| `invalid_pubkey` | A worker/adapter reported invalid public key material. |
| `tweak_out_of_range` | Tagged hash interpreted as scalar was invalid. |
| `internal` | Unexpected adapter/runtime failure. |

## Sender Fields

Additional fields for `kind = "send"`:

| Field | Type | Notes |
| --- | --- | --- |
| `input_private_key_sum` | hex string or `null` | Aggregate sender scalar after taproot parity handling. |
| `sender_shared_secrets` | object[] | One entry per unique `scan_pubkey`. |
| `acceptable_output_sets` | string[][] | Canonical list of valid x-only output sets. Inner lists are sorted and unique. |
| `output_count_options` | integer[] | Convenience field derived from `acceptable_output_sets`. |

Each `sender_shared_secrets` entry has:

| Field | Type | Notes |
| --- | --- | --- |
| `scan_pubkey` | hex string | Compressed scan pubkey. |
| `shared_secret` | hex string or `null` | Group shared secret when computed. |

### Sender Comparison Rule

The expected contract may contain more than one acceptable output set. An actual result is valid when every output set it presents is a member of the expected `acceptable_output_sets`.

This matters for official labeled-recipient cases where several recipient orderings are valid.

## Receiver Fields

Additional fields for `kind = "receive"`:

| Field | Type | Notes |
| --- | --- | --- |
| `receiving_addresses` | string[] | Derived silent payment addresses in canonical order. |
| `input_pubkey_sum` | hex string or `null` | Compressed aggregate input pubkey when defined. |
| `tweak` | hex string or `null` | Compressed tweak point when defined. |
| `shared_secret` | hex string or `null` | Compressed shared secret when defined. |
| `detailed_outputs_available` | boolean | Whether full output details are part of the expected contract. |
| `found_output_count` | integer | Number of outputs found by scanning. |
| `found_outputs` | object[] | Detailed outputs, sorted canonically when present. |

Each `found_outputs` entry has:

| Field | Type | Notes |
| --- | --- | --- |
| `pub_key` | hex string | X-only pubkey of the found output. |
| `priv_key_tweak` | hex string | Scalar tweak needed to derive the receiving private key. |

### Receiver Comparison Rule

- If `detailed_outputs_available = true`, `found_outputs` must match exactly after canonical sorting.
- If `detailed_outputs_available = false`, comparison only requires `found_output_count` to match.

This supports official cases such as the `K_max` boundary vector where upstream publishes only the count.

## Canonicalization

- `notes` are sorted and de-duplicated.
- Sender output sets are compared as sorted unique x-only pubkey lists.
- Receiver detailed outputs are sorted by `(pub_key, priv_key_tweak)`.
- Sender shared secret entries are sorted by `scan_pubkey`.

## Current Usage

- The vendored upstream oracle is normalized into this contract for the full official vector surface.
- Derived official v2 cases under `tests/vectors/bip352/derived/v2/` carry one `.expected.json` file per case using this contract.
- Command adapters and compiled semantic workers should normalize their results into this contract before comparison.
