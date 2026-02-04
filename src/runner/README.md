# Runner

This folder contains the minimal compiled runner and will expand to the full orchestration layer.

Planned responsibilities:
- Manage worker lifecycles.
- Batch inputs to reduce overhead.
- Capture worker logs and outputs.

Current binary:
- `sp_differ_runner.cpp` provides a minimal CLI that loads a worker, executes a case, validates the output format, and returns stable exit codes.
- `sp_differ_compare.cpp` provides a minimal differential runner that compares two workers.

Usage:
- `build/sp_differ_runner tests/vectors/example.hex`
- `build/sp_differ_runner tests/vectors/example.hex --worker build/libsp_differ_worker.dylib`
- `build/sp_differ_runner tests/vectors/example.hex --worker rust`
- `build/sp_differ_compare tests/vectors/example.hex --left cpp --right rust`
