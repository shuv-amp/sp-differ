# Runner Contract

This document defines the expected behavior for the minimal runner used in CI and developer workflows. It is intentionally small and stable so future tooling remains consistent.

## Purpose

The runner executes a single case through a worker, validates the output format, and returns a clear exit status. It must be deterministic and free of side effects beyond its output.

## Inputs

- A single case payload (hex or binary) that follows `../spec/FORMAT.md`.
- Optional worker selection.
- For `version = 1` cases, `--worker cpp` and `--worker rust` are aliases for the default byte-worker build outputs.
- For `version = 2` cases, `--worker spdk`, `--worker silent-payments`, `--worker bip352`, and `--worker go-bip352` are aliases for the default semantic worker build outputs.

## Outputs

- A single-line summary to stdout on success.
- A single-line summary to stderr on failure.
- No additional output unless explicitly requested by flags.

## Exit Codes

- `0`: success, output validated.
- `2`: invalid input, invalid output, or worker failure.
- `>2`: reserved for unexpected runner errors.

The runner does not interpret semantic success. For v1 it validates the byte output payload; for v2 it validates the semantic JSON result shape. A non-`ok` semantic status is still considered a valid output when the result matches the contract.

## Determinism

- The runner must not generate random values.
- The same input case must yield the same output every run.
- Version 2 request construction must be deterministic for the same case path, network, and optional expectation metadata.

## Failure Handling

- The runner must not crash on malformed input.
- All errors should be surfaced with a short, actionable message.

## Compatibility

- The runner may evolve, but the exit codes and summary line semantics must remain stable.
