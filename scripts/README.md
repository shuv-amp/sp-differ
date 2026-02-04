# Scripts

This folder will contain small developer scripts for running vectors, fuzzing, and report generation. Scripts should be deterministic, avoid network calls by default, and print clear repro commands.

Current scripts:
- `parse_case.py` parses and validates a v1 case file and prints a summary.
- `validate_output.py` validates a worker output payload against the v1 output format.
- `runner_smoke.py` performs an end-to-end worker smoke check with a clear exit code.

Make targets:
- `make worker` builds the C++ worker stub.
- `make runner` builds the compiled runner.
- `make compare` builds the compiled differential runner.
- `make check` runs core I/O, case parser, and header validation smoke tests.
- `make smoke` runs the end-to-end smoke check with the compiled runner.
- `make worker-rust` builds the Rust worker stub and copies the shared library into `build/`.
- `make smoke-rust` runs the compiled runner against the Rust worker stub.
- `make diff` runs the differential runner against the C++ and Rust stubs.
