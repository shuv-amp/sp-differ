#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Smoke-test the source comment discipline checker."""

import subprocess
import sys
import tempfile
from pathlib import Path


def _run(path: Path):
    return subprocess.run(
        [sys.executable, "scripts/check_source_comment_discipline.py", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="sp_differ_source_comments_") as tmpdir:
        tmp = Path(tmpdir)
        clean = tmp / "clean.cpp"
        flagged = tmp / "flagged.py"

        clean.write_text(
            "// Canonicalize the request path before comparing fixture output.\nint main() { return 0; }\n",
            encoding="utf-8",
        )
        flagged.write_text(
            "# {} replace this robust helper later\n".format("TO" "DO")
            + '"""This clearly needs a better description."""\n',
            encoding="utf-8",
        )

        clean_result = _run(clean)
        if clean_result.returncode != 0:
            raise SystemExit("expected clean source comment to pass:\n{}".format(clean_result.stdout + clean_result.stderr))

        flagged_result = _run(flagged)
        if flagged_result.returncode == 0:
            raise SystemExit("expected flagged source comment to fail")
        if "todo_marker" not in flagged_result.stdout:
            raise SystemExit("missing todo_marker finding")
        if "hype_without_evidence" not in flagged_result.stdout:
            raise SystemExit("missing hype_without_evidence finding")
        if "vague_certainty" not in flagged_result.stdout:
            raise SystemExit("missing vague_certainty finding")

    print("source comment discipline smoke OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
