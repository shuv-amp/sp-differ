# CLI

`main.cpp` builds the compiled `sp_differ_cli` binary.

Current responsibilities:
- accept case paths plus worker/semantic-worker selection
- verify mixed v1 and v2 official-vector suites
- emit machine-readable JSON and markdown reports through `src/reporter`
