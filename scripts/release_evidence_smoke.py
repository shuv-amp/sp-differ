#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Smoke-test release evidence manifest generation."""

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "generate_release_evidence_manifest.py"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="sp_differ_release_evidence_") as tmp_dir:
        tmp_root = Path(tmp_dir)
        alpha = tmp_root / "alpha.txt"
        beta = tmp_root / "beta.txt"
        report_path = tmp_root / "release_evidence.json"
        markdown_path = tmp_root / "release_evidence.md"

        alpha_bytes = b"alpha\n"
        beta_bytes = b"beta\n"
        alpha.write_bytes(alpha_bytes)
        beta.write_bytes(beta_bytes)

        subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--path",
                str(alpha),
                "--path",
                str(beta),
                "--json-out",
                str(report_path),
                "--markdown-out",
                str(markdown_path),
            ],
            cwd=ROOT,
            check=True,
        )

        report = json.loads(report_path.read_text(encoding="utf-8"))
        if len(report["files"]) != 2:
            raise RuntimeError("expected two evidence files")

        expected = {
            str(alpha): _sha256(alpha_bytes),
            str(beta): _sha256(beta_bytes),
        }
        observed = {item["path"]: item["sha256"] for item in report["files"]}
        if observed != expected:
            raise RuntimeError("unexpected sha256 values in evidence manifest")

    print("release evidence smoke OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
