# Architecture

This document describes the core structure and boundaries of SP-DIFFER. It is intentionally small and stable.

## Pipeline Architecture

The harness ingests a canonical case, routes it through the appropriate byte-worker or semantic adapter layer, compares the resulting payloads, and serializes replayable artifacts.

1. **Ingest**: Cases are sourced from the pinned official corpus or generated replay artifacts.
2. **Normalization**: Canonical parser rules ensure uniform cross-implementation input.
3. **Execution**: v1 cases target the byte-worker ABI; v2 cases utilize the semantic adapter / worker path.
4. **Validation**: The comparator evaluates results against the reference oracle or expectation sidecars.
5. **Output**: Findings are persisted as JSON/Markdown reports and actionable replay bundles.

## Components

### Corpus Tooling

The repo does not ship a single runtime "input generator" component. Instead it ships pinned official vectors, derived corpora, deterministic corpus refresh scripts, and fuzz runners that generate replayable request and artifact material.

### Normalizer

Applies the canonical rules so that every implementation receives the same logical input. This prevents false positives caused by ordering or encoding differences.

### Semantic Bridge

For v2 cases, the native C++ semantic bridge parses the binary case format once, constructs the semantic request, and routes execution to command adapters or semantic worker shared libraries.

### Workers and Adapters

The v1 path uses byte-worker shared libraries behind `../ffi/sp_differ.h`. The v2 path uses command adapters and semantic worker shared libraries behind `../ffi/sp_differ_semantic.h`.

### Comparator

Performs byte-level comparison for v1 outputs and expectation-aware semantic comparison for v2 outputs. The compiled compare binary classifies mismatches and runtime failures.

### Reporter and CLI

The reporter writes JSON and Markdown summaries plus replay artifacts. The compiled CLI and the Python wrapper surface those reports through local verification, replay, and release-check workflows.

### Corpus and Artifacts

Stores known-good cases and regression cases. Artifacts include input cases, outputs, and metadata with commit hashes.

## Boundaries and Interfaces

The core runner and comparator are implementation-agnostic. Workers communicate through a stable C ABI defined in `ffi/` and through a canonical case format defined in `spec/`.

## Determinism and Replay

Seeded replay applies to the deterministic fuzz runners and generated-case workflows. The repo also supports exact replay from saved failure artifacts, pinned vectors, and retained regression cases. Not every workflow is reduced to a single seed value.

## Performance Notes

The harness batches inputs to reduce FFI overhead. Heavy computation stays inside worker implementations.

## Known Scope

The v1 byte-worker handles P2WPKH, P2TR keypath, and P2SH-P2WPKH input types. P2PKH is not implemented in the v1 worker. The v2 semantic path covers P2PKH through the reference adapter.
