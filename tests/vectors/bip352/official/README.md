# Official BIP352 Snapshot

This directory stores the official BIP 352 `send_and_receive_test_vectors.json` snapshot exactly as published upstream, together with a local manifest that records provenance and checksum data.

It also stores a vendored copy of the exact upstream Python reference bundle needed to run the official vectors offline from this repository.

- Upstream project: `bitcoin/bips`
- Source path: `bip-0352/send_and_receive_test_vectors.json`
- Companion reference implementation: `bip-0352/reference.py`
- Vendored reference bundle root: `tests/vectors/bip352/official/reference/`

Do not edit the vendored JSON or vendored reference files by hand. Refresh them with `python3 scripts/fetch_bip352_vectors.py` or `make vectors-refresh`.
