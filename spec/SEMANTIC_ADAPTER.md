# Semantic Adapter Contract

## Purpose

`./SEMANTIC_CONTRACT.md` defines what a normalized sender or receiver result looks like.

This document defines the execution bridge that real implementations use to produce that result from a `case format v2` input without each implementation having to parse the repository's binary test fixture format on its own.

The intent is:

1. `tests/vectors/bip352/derived/v2/*.hex` remains the canonical corpus.
2. The runner parses those bytes once into a stable JSON request.
3. Adapters consume that JSON request and emit a semantic result matching `./SEMANTIC_CONTRACT.md`.
4. The runner compares the adapter result to the vendored oracle expectations.

## Transport

The semantic adapter contract is transport-neutral.

The default command transport is:

- Input: UTF-8 JSON on `stdin`
- Output: UTF-8 JSON on `stdout`
- Success exit code: `0`
- Failure exit code: nonzero

The same request/response JSON can also be transported through the compiled semantic worker ABI defined in `../ffi/sp_differ_semantic.h`.

Adapters must not print non-JSON material to `stdout`.

## Request

Top-level fields:

- `semantic_adapter_request_version`: integer, currently `1`
- `case_format_version`: integer, currently `2`
- `kind`: `"send"` or `"receive"`
- `network`: currently `"mainnet"`, `"testnet"`, `"regtest"`, or `"signet"`
- `silent_payment_version`: integer, currently `0`
- `seed`: copied from the v2 case header for provenance/debugging
- `flags`: copied from the v2 case header for provenance/debugging
- `source`: the exact `source` object that must be echoed back in the semantic result
- `inputs`: array of parsed input objects
- `expectation_hints`: optional non-semantic execution hints supplied by the runner

Each `inputs[]` item contains:

- `outpoint_txid`: 32-byte txid hex in normal display order
- `outpoint_vout`: integer
- `input_type`: one of `p2wpkh`, `p2tr`, `p2sh-p2wpkh`, `p2pkh`
- `prevout_script_pubkey`: hex or `null`
- `script_sig`: hex or `null`
- `txinwitness`: serialized witness-stack hex or `null`
- `txinwitness_stack`: decoded witness stack as an array of hex strings
- `privkey`: hex or `null`
- `pubkey`: hex or `null`

`send` requests additionally contain:

- `recipient_groups`: array of `{scan_pubkey, spend_pubkey, count}`

`receive` requests additionally contain:

- `outputs_to_scan`: array of x-only output pubkeys as 32-byte hex
- `receiver_keys`: `{scan_privkey, spend_privkey}`
- `labels`: array of integers

Current `expectation_hints` fields:

- `detailed_outputs_required`: boolean used only for receiver-side execution

This hint is intentionally narrow. It tells an adapter whether the current harness requires exact `found_outputs` material or only `found_output_count`. It does not include expected outputs, tweaks, or secrets.

## Response

The adapter response is a semantic result object validated by `./SEMANTIC_CONTRACT.md`.

That means adapters must emit:

- the same `source`
- the same `kind`
- `case_format_version = 2`
- `semantic_contract_version = 1`

and then the normalized sender or receiver fields required by the semantic contract.

## Comparison Semantics

The runner uses the same comparison rules as the oracle path:

- sender adapters may return one or more acceptable output sets, as long as every returned set is allowed by the expected contract
- receiver adapters must match `found_output_count`
- receiver adapters may return detailed outputs even when the official expectation is count-only

## Current Adapters

- `adapters/reference/semantic_adapter.py`: wraps the vendored upstream BIP352 reference bundle through this contract
- `adapters/spdk_rust/`: Rust adapter backed by the public `silentpayments` crate, exposed as both a command adapter and a semantic worker shared library
- `adapters/silent_payments_rust/`: Rust adapter backed by the public `silent-payments` crate, exposed as both a command adapter and a semantic worker shared library
- `adapters/bip352_rust/`: Rust adapter backed by the public `bip352` crate, exposed as both a command adapter and a semantic worker shared library
- `adapters/go_bip352/`: Go-backed adapter, exposed as both a command adapter and a semantic worker shared library
- `adapters/bdk_sp_rust/`: Rust adapter backed by `bdk-sp`, currently exposed as a command adapter

## Why This Is Separate From The C ABI

The existing compiled worker ABI in `../ffi/sp_differ.h` is still the minimal v1 byte-buffer interface used by the C++ and Rust byte-worker surfaces.

The repo now also defines a separate semantic worker ABI in `../ffi/sp_differ_semantic.h` for compiled execution of this same request/response contract.

The semantic adapter contract is deliberately higher level:

- it lets real implementations integrate now
- it keeps the semantic shape stable across command and shared-library transports
- it keeps the repository's binary corpus and the implementation-facing execution surface decoupled
