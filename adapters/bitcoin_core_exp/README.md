# Bitcoin Core Experimental Adapter

This directory contains the opt-in experimental semantic adapter for local Bitcoin Core Silent Payments branches.

It is intentionally not part of the default `make adapters`, CI, or release-readiness lanes.

## What It Runs

- `semantic_adapter.py` is the command adapter entrypoint.
- `bitcoin_sp_semantic_helper.cpp` is the repo-owned helper source compiled against a local Bitcoin Core checkout.

The helper uses Bitcoin Core's `common/bip352` and vendored `secp256k1` Silent Payments surfaces directly. It does not call wallet RPCs.

## Prerequisites

The target Bitcoin Core checkout must expose:

- `src/common/bip352.h`
- `src/secp256k1/include/secp256k1_silentpayments.h`

The supported builder is:

```bash
python3 scripts/build_bitcoin_core_helper.py --bitcoin-root /path/to/bitcoin
```

That script can also reuse a non-default build directory:

```bash
python3 scripts/build_bitcoin_core_helper.py \
  --bitcoin-root /path/to/bitcoin \
  --bitcoin-build-dir /path/to/bitcoin/build_sp_libs
```

## Current Posture

This adapter is for local maintainer research against active Bitcoin Core Silent Payments branches.

As of April 11, 2026, the current draft sending branch at `bitcoin/bitcoin#28201` head `db58cb7cb228ad6a88de29ea2b11a9ee1ce03368` still lands at `54/55` official derived cases. The only remaining mismatch is `official_case_26_receive_00`, and the retained regression lane stays green. Treat that mismatch as branch-specific evidence, not as a repository failure.
