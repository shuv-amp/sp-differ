# Semantic Regressions

This suite stores two kinds of retained semantic cases:

- promoted semantic mismatches and execution failures from real adapter or semantic-worker runs
- retained official edge cases that are kept in the regression lane because they exercise divergence-prone behavior

Promoted failure entries preserve:

- the original `case.hex`
- the oracle `expected.json`
- the observed adapter request and summary
- the observed actual result when one was produced
- stable provenance metadata

Retained official edge cases store pinned request/provenance files and reference the vendored derived v2 case and expectation files directly.

The manifest at `tests/regressions/semantic/manifest.json` is intentionally compatible with `scripts/run_semantic_adapter_cases.py`, so the regression suite can reuse the same compare engine as the main official-vector flow. The manifest is the source of truth for active regressions; it may legitimately be empty when all known-good adapters are green.

Promotion workflow:

```bash
python3 scripts/intake_semantic_regressions.py --artifact-dir build/<artifact-root>/<case-id>
```

Replay workflow:

```bash
python3 scripts/run_semantic_regressions.py --adapter-name reference --adapter-cmd "python3 adapters/reference/semantic_adapter.py"
```
