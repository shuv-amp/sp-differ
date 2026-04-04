#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Smoke-test the release prerequisite audit."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def _run(args, cwd):
    return subprocess.run(
        [sys.executable] + args,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    script = repo_root / "scripts" / "check_release_prereqs.py"

    with tempfile.TemporaryDirectory(prefix="sp_differ_release_prereqs_") as tmpdir:
        tmp = Path(tmpdir)
        good_root = tmp / "good"
        good_root.mkdir()
        (good_root / "LICENSE").write_text("test license\n", encoding="utf-8")
        (good_root / "SECURITY.md").write_text(
            "# Security Policy\n\nMaintainer signing fingerprint: `0123 4567 89AB CDEF 0123 4567 89AB CDEF 0123 4567`\n",
            encoding="utf-8",
        )

        passed = _run(
            [
                str(script),
                "--repo-root",
                str(good_root),
                "--json-out",
                str(tmp / "good.json"),
                "--markdown-out",
                str(tmp / "good.md"),
            ],
            cwd=repo_root,
        )
        if passed.returncode != 0:
            raise SystemExit("expected prereq check to pass:\n{}".format(passed.stdout + passed.stderr))

        failed_root = tmp / "failed"
        failed_root.mkdir()
        (failed_root / "SECURITY.md").write_text(
            "# Security Policy\n\nNo fingerprints published yet.\n",
            encoding="utf-8",
        )
        failed = _run(
            [
                str(script),
                "--repo-root",
                str(failed_root),
                "--json-out",
                str(tmp / "failed.json"),
                "--markdown-out",
                str(tmp / "failed.md"),
            ],
            cwd=repo_root,
        )
        if failed.returncode == 0:
            raise SystemExit("expected prereq check to fail for missing license and fingerprint")
        report = json.loads((tmp / "failed.json").read_text(encoding="utf-8"))
        if report["status"] != "failed":
            raise SystemExit("expected failed report status")
        if len(report["missing"]) != 2:
            raise SystemExit("expected two missing items in failed prereq report")

    print("release prereqs smoke OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
