# Core

This folder will contain implementation-agnostic logic such as case parsing, normalization, comparison, and shared types.

Planned responsibilities:
- Case parsing and validation.
- Normalization rules and helpers.
- Comparator and diff classification.
- Canonical serialization for artifacts.

Current modules:
- `io.h` and `io.cpp` provide case file decoding and output validation helpers.
- `case.h` and `case.cpp` provide a strict v1 case parser.
- `validate.h` and `validate.cpp` provide fast header sanity checks.
