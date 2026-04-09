#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify that a shared library exports the expected public ABI symbols."""

from __future__ import annotations

import argparse
import ctypes
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ROOT_STR = str(ROOT)


def _resolve_repo_library(raw_library: str) -> Path:
    candidate = Path(raw_library)
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    resolved = Path(os.path.realpath(candidate))
    try:
        common = os.path.commonpath([ROOT_STR, str(resolved)])
    except ValueError as exc:
        raise ValueError("path escapes repository root: {}".format(raw_library)) from exc
    if common != ROOT_STR:
        raise ValueError("path escapes repository root: {}".format(raw_library))
    return resolved


def load_library(library: Path) -> ctypes.CDLL:
    try:
        return ctypes.CDLL(str(library))
    except OSError as exc:
        print(f"error: failed to load shared library {library}: {exc}", file=sys.stderr)
        raise SystemExit(1)


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

    library = _resolve_repo_library(args.library)
    if not library.is_file():
        print(f"error: library not found: {library}", file=sys.stderr)
        return 1

    handle = load_library(library)
    missing = []
    for symbol in args.symbols:
        try:
            getattr(handle, symbol)
        except AttributeError:
            missing.append(symbol)
    if missing:
        for symbol in missing:
            print(f"missing exported symbol: {symbol}", file=sys.stderr)
        return 1

    print(f"ABI symbols OK: {library}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
