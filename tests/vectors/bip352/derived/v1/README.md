# Derived V1 Subset

This directory stores the subset of official BIP352 sending vectors that fit the current SP-DIFFER case format v1 without changing the format.

These files are derived artifacts, not official upstream vectors.

- Source of truth: `tests/vectors/bip352/official/send_and_receive_test_vectors.json`
- Generator: `python3 scripts/generate_bip352_projected_cases.py`
- Scope: sender-side entries only
- Current limitation: receiving/scanning vectors do not fit v1 and are intentionally not forced into this subset
