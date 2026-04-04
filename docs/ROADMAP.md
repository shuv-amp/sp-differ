# Roadmap

This roadmap prioritizes correctness and reproducibility before performance.

## Phase 0: Foundations

- SHIPPED: Define the canonical case format, normalization rules, and worker interface.
- SHIPPED: Validate the vendored current semantic corpus across the current adapter and worker matrix.

## Phase 1: Differential Harness

- SHIPPED: Build the comparator, reporter, and CLI runner.
- SHIPPED: Produce replayable reproduction artifacts for the mismatch paths exercised by the harness.

## Phase 2: Fuzzing

- SHIPPED: Add fuzz harnesses, seed corpus, and minimization.
- REMAINING: Let the existing deterministic fuzz infrastructure accumulate longer soak evidence.

## Phase 3: Community Integration

- SHIPPED: Package the project for CI use and document workflows.
- SHIPPED: Add additional implementations. The current canonical gate includes five independent non-reference implementation surfaces: four Rust-backed adapters (`silentpayments`, `silent-payments`, `bip352`, and `bdk-sp`) plus the external Go-backed `go-bip352` adapter, alongside the vendored reference path.

## Phase 4: Release Hardening

- REMAINING: Let scheduled fuzz soak build historical confidence.
- SHIPPED: Keep release workflows as the current release baseline.
- REMAINING: Expand from library-level coverage into wallet-facing ecosystem integrations only when a target meets deterministic, headless, and reproducible integration requirements.

Decision gate as of March 29, 2026:

1. No wallet-facing target currently clears all SP-DIFFER reproducibility constraints.
2. Wallet-facing expansion therefore remains intentionally unimplemented in this cycle.
3. The public CLI/reporting surface and converged v1/v2 compiled runner remain the current release baseline while ecosystem targets mature.
