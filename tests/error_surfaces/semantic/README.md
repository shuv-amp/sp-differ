# Semantic Error Surfaces

This suite tracks semantic-contract statuses that are intentionally covered
outside the valid structured fuzz corpus.

Why this exists:

- the valid semantic corpus is reserved for oracle-backed, valid requests
- some semantic status enum values are defensive or reserved surfaces rather
  than reference-oracle outcomes
- forcing those paths into the valid corpus would dilute the signal in the
  fuzz/introspection reports

The manifest at `tests/error_surfaces/semantic/manifest.json` records two kinds
of coverage:

- synthetic semantic-result fixtures that must validate through the shared
  semantic contract and compiled compare path
- deterministic byte-worker runtime cases for defensive ABI statuses that are
  actually reachable without fault injection

The `internal` semantic status is currently covered only by the synthetic
contract fixture. The in-tree worker implementations do not expose a stable,
deterministic runtime trigger for `internal` without fault injection, so we
track it as a reserved contract surface instead of pretending it belongs in the
valid corpus.
