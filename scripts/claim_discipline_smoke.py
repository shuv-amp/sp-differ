#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Smoke-test the public claim-discipline checker."""

import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _run(path):
    return subprocess.run(
        [sys.executable, "scripts/check_claim_discipline.py", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )


def main():
    temp_root = ROOT / ".tmp_smoke"
    temp_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sp_differ_claims_", dir=temp_root) as tmpdir:
        tmp = Path(tmpdir)
        clean = tmp / "clean.md"
        flagged = tmp / "flagged.md"

        clean.write_text(
            "# Clean\n\nThis report ranks candidates by the evidence captured in this repository.\n",
            encoding="utf-8",
        )
        flagged.write_text(
            "# Flagged\n\nThis is the best implementation overall and this folder {} more later.\n".format(
                "will con" "tain"
            ),
            encoding="utf-8",
        )

        clean_result = _run(clean)
        if clean_result.returncode != 0:
            raise SystemExit("expected clean file to pass:\n{}".format(clean_result.stdout + clean_result.stderr))

        flagged_result = _run(flagged)
        if flagged_result.returncode == 0:
            raise SystemExit("expected flagged file to fail")
        if "unsupported_superlative" not in flagged_result.stdout:
            raise SystemExit("missing unsupported_superlative finding")
        if "future_tense_claim" not in flagged_result.stdout:
            raise SystemExit("missing future_tense_claim finding")

    print("claim discipline smoke OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
