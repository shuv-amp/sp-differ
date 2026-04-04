# Reporter

`reporter.cpp` and `reporter.h` implement the compiled reporting surface used by
`sp_differ_cli`.

Current responsibilities:
- write suite summaries as JSON
- render human-readable markdown reports
- preserve per-case status, implementation, and mismatch detail
