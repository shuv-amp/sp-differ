#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify that a shared library exports the expected public ABI symbols."""

from __future__ import annotations

import argparse
import ctypes
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

def _library_ext() -> str:
    if sys.platform == "darwin":
        return "dylib"
    if sys.platform == "win32":
        return "dll"
    return "so"


def _shared_library_name(stem: str) -> str:
    ext = _library_ext()
    if sys.platform == "win32":
        return f"{stem}.{ext}"
    return f"lib{stem}.{ext}"


TARGET_LIBRARY_PATHS = {
    "bip352-semantic": ROOT
    / "adapters"
    / "bip352_rust"
    / "target"
    / "debug"
    / _shared_library_name("sp_differ_semantic_worker_bip352"),
    "cpp-worker": ROOT / "build" / _shared_library_name("sp_differ_worker"),
    "go-bip352-semantic": ROOT / "build" / _shared_library_name("sp_differ_semantic_worker_go_bip352"),
    "rust-worker": ROOT / "build" / _shared_library_name("sp_differ_worker_rust"),
    "silent-payments-semantic": ROOT
    / "adapters"
    / "silent_payments_rust"
    / "target"
    / "debug"
    / _shared_library_name("sp_differ_semantic_worker_silent_payments"),
    "spdk-semantic": ROOT
    / "adapters"
    / "spdk_rust"
    / "target"
    / "debug"
    / _shared_library_name("sp_differ_semantic_worker_spdk"),
}


def load_library(library: Path) -> ctypes.CDLL:
    try:
        return ctypes.CDLL(str(library))
    except OSError as exc:
        print(f"error: failed to load shared library {library}: {exc}", file=sys.stderr)
        raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        required=True,
        choices=sorted(TARGET_LIBRARY_PATHS),
        help="named shared library target to inspect",
    )
    parser.add_argument(
        "--symbol",
        action="append",
        dest="symbols",
        required=True,
        help="expected exported symbol",
    )
    args = parser.parse_args()

    library = TARGET_LIBRARY_PATHS[args.target]
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
