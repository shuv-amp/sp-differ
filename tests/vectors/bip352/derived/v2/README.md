# Derived V2 Set

This directory stores the full official BIP352 send and receive surface encoded into SP-DIFFER case format v2.

These files are derived artifacts, not official upstream vectors.

- Source of truth: `tests/vectors/bip352/official/send_and_receive_test_vectors.json`
- Generator: `python3 scripts/generate_bip352_v2_cases.py`
- Scope: all official sending entries and all official receiving entries
- Expectation format: `spec/SEMANTIC_CONTRACT.md`
- Oracle check: `python3 scripts/run_bip352_v2_oracle_cases.py`

Each `.hex` file is a v2 case payload.
Each matching `.expected.json` file is the normalized semantic comparison contract derived from that v2 case and cross-checked against the pinned official upstream expectations.
