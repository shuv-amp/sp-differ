#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Smoke test the tracked semantic error-surface lane."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run_semantic_error_surfaces.py"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="sp_differ_semantic_error_surface_smoke_") as tmp:
        tmp_root = Path(tmp)
        report_path = tmp_root / "report.json"
        markdown_path = tmp_root / "report.md"
        proc = subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                "--json-out",
                str(report_path),
                "--markdown-out",
                str(markdown_path),
            ],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        _require(proc.returncode == 0, "expected semantic error surfaces run to pass")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        _require(report["status"] == "passed", "expected passing semantic error surface report")
        _require(
            report["covered_statuses"]
            == ["internal", "invalid_input", "invalid_pubkey", "tweak_out_of_range"],
            "unexpected covered semantic statuses",
        )
        _require(
            report["counts"]["synthetic_contract_cases"] == 4,
            "expected four synthetic contract fixtures",
        )
        _require(
            report["counts"]["byte_worker_runtime_cases"] == 3,
            "expected three byte-worker runtime cases",
        )
        _require(not report["failures"], "expected no error-surface failures")

    print("semantic error surface smoke OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
