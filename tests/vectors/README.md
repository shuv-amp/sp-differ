# Test Vectors

This folder will store official BIP 352 test vectors and any normalized derivative sets. Vectors are stored exactly as published and should not be edited. Any modifications go to a separate derived file with a clear provenance note.

`example.hex` is a canonical v1 case used as a reference for parsers. See `spec/EXAMPLE.md` for the decoded layout.
`example_v2.hex` is a canonical v2 case used to exercise the richer input/recipient/receiver sections. See `spec/EXAMPLE_V2.md`.
`output_ok.hex` is a minimal successful output payload. See `spec/OUTPUT_EXAMPLE.md`.
`bip352/official/` stores the vendored official BIP352 send-and-receive vector snapshot, checksum manifest, and the pinned upstream reference bundle used as an offline semantic oracle.
`bip352/derived/v1/` stores the subset of official sending vectors that fit the current SP-DIFFER case format v1 without changing the format.
`bip352/derived/v2/` stores the full official send/receive surface encoded into SP-DIFFER case format v2, together with normalized semantic expectation files and the corpus consumed by the semantic adapter runner.
