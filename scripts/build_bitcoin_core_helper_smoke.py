#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Smoke tests for the experimental Bitcoin Core helper builder."""

import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_bitcoin_core_helper.py"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def main() -> int:
    missing = _run("--bitcoin-root", str(ROOT / "missing-bitcoin-checkout"), "--dry-run")
    _require(missing.returncode == 2, "expected missing checkout to fail")
    _require("missing required path" in missing.stderr, "expected targeted missing-checkout error")

    with tempfile.TemporaryDirectory(prefix="sp_differ_bitcoin_core_helper_") as tmp_dir:
        tmp_root = Path(tmp_dir)
        fake_root = tmp_root / "bitcoin"
        fake_root.mkdir(parents=True, exist_ok=True)
        (fake_root / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.22)\n", encoding="utf-8")

        missing_headers = _run("--bitcoin-root", str(fake_root), "--dry-run")
        _require(missing_headers.returncode == 2, "expected missing headers to fail")
        _require("src/common/bip352.h" in missing_headers.stderr, "expected missing header path in error")

        (fake_root / "src/common").mkdir(parents=True, exist_ok=True)
        (fake_root / "src/secp256k1/include").mkdir(parents=True, exist_ok=True)
        (fake_root / "src/univalue/include").mkdir(parents=True, exist_ok=True)
        (fake_root / "src/common/bip352.h").write_text("// fake\n", encoding="utf-8")
        (fake_root / "src/secp256k1/include/secp256k1_silentpayments.h").write_text(
            "// fake\n",
            encoding="utf-8",
        )
        (fake_root / "src/univalue/include/univalue.h").write_text("// fake\n", encoding="utf-8")

        dry_run = _run("--bitcoin-root", str(fake_root), "--dry-run")
        _require(dry_run.returncode == 0, "expected dry-run to pass on valid fake layout")
        _require("configure:" in dry_run.stdout, "expected configure command in dry-run output")
        _require("build:" in dry_run.stdout, "expected build command in dry-run output")
        _require("compile:" in dry_run.stdout, "expected compile command in dry-run output")
        _require("bitcoin_common" in dry_run.stdout, "expected build target list in dry-run output")
        _require(
            "bitcoin_sp_semantic_helper.cpp" in dry_run.stdout,
            "expected helper source path in compile command",
        )

    print("bitcoin core helper build smoke OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
