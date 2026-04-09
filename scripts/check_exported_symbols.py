#!/usr/bin/env python3
"""Verify that a shared library exports the expected public ABI symbols."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def load_symbols(library: Path) -> set[str]:
    commands = [
        ["nm", "-gU", str(library)],
        ["nm", "-D", "--defined-only", str(library)],
        ["nm", "-g", str(library)],
    ]
    last_error: subprocess.CalledProcessError | None = None
    for command in commands:
        try:
            completed = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
            )
            return parse_nm_output(completed.stdout)
        except FileNotFoundError:
            print("error: nm is required to verify exported symbols", file=sys.stderr)
            raise SystemExit(1)
        except subprocess.CalledProcessError as exc:
            last_error = exc
    assert last_error is not None
    print(last_error.stderr.strip() or last_error.stdout.strip(), file=sys.stderr)
    raise SystemExit(last_error.returncode)


def parse_nm_output(output: str) -> set[str]:
    symbols: set[str] = set()
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        symbol = parts[-1]
        if symbol == "U":
            continue
        symbols.add(symbol)
        if symbol.startswith("_") and len(symbol) > 1:
            symbols.add(symbol[1:])
    return symbols


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True, help="shared library to inspect")
    parser.add_argument(
        "--symbol",
        action="append",
        dest="symbols",
        required=True,
        help="expected exported symbol",
    )
    args = parser.parse_args()

    library = Path(args.library)
    if not library.is_file():
        print(f"error: library not found: {library}", file=sys.stderr)
        return 1

    exported = load_symbols(library)
    missing = [symbol for symbol in args.symbols if symbol not in exported]
    if missing:
        for symbol in missing:
            print(f"missing exported symbol: {symbol}", file=sys.stderr)
        return 1

    print(f"ABI symbols OK: {library}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
