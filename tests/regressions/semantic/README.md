# Semantic Regressions

This suite stores three kinds of retained semantic cases:

- promoted semantic mismatches and execution failures from real adapter or semantic-worker runs
- retained official edge cases that are kept in the regression lane because they exercise divergence-prone behavior
- request-backed adapter-scoped divergences that do not map cleanly back to a single pinned `.hex` case

Promoted failure entries preserve:

- the original `case.hex`
- the oracle `expected.json`
- the observed adapter request and summary
- the observed actual result when one was produced
- stable provenance metadata

Retained official edge cases store pinned request/provenance files and reference the vendored derived v2 case and expectation files directly.

Request-backed divergences preserve:

- the exact minimized `request.json` that triggered the divergence
- the oracle `expected.json`
- the targeted adapter's `observed_actual.json`
- a stable `expectation_mode: observed_actual` manifest entry so the regression lane stays green while the upstream bug still reproduces and flips red once the adapter changes behavior

Some retained edge cases intentionally appear twice:

- once as a normal oracle-expected regression entry scoped to the adapters that are currently expected to pass it
- again as adapter-scoped `observed_actual` entries for implementations with a known upstream bug

That pattern lets the general regression story stay mathematically correct while still tracking a known divergence until upstream behavior changes.

The manifest at `tests/regressions/semantic/manifest.json` is intentionally compatible with `scripts/run_semantic_adapter_cases.py`, so the regression suite can reuse the same compare engine as the main official-vector flow. The manifest is the source of truth for active regressions; it may legitimately be empty when all known-good adapters are green.

Manifest notes:

- `request_path` takes precedence over `path` when both are present, so minimized request mutations can be replayed exactly without rebuilding them from the source case.
- `adapter_name` or `adapter_names` scopes a retained case to the adapters that are expected to see it.
- `expectation_mode: observed_actual` turns a retained case into a tracked known divergence. In that mode the selected adapter must continue matching the stored `observed_actual.json`; if it starts matching the oracle instead, the regression lane fails so maintainers can prune or convert the entry.

Promotion workflow:

```bash
python3 scripts/intake_semantic_regressions.py --artifact-dir build/<artifact-root>/<case-id>
```

Known-divergence promotion workflow:

```bash
python3 scripts/intake_semantic_regressions.py \
  --artifact-dir build/<artifact-root>/<case-id> \
  --expectation-mode observed_actual
```

Replay workflow:

```bash
python3 scripts/run_semantic_regressions.py --adapter-name reference --adapter-cmd "python3 adapters/reference/semantic_adapter.py"
```
