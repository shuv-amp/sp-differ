#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Smoke-test the source comment discipline checker."""

import importlib.util
import tempfile
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "check_source_comment_discipline.py"

_SPEC = importlib.util.spec_from_file_location("check_source_comment_discipline", MODULE_PATH)
assert _SPEC is not None and _SPEC.loader is not None
MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(MODULE)


def main() -> int:
    temp_root = ROOT / ".tmp_smoke"
    temp_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="sp_differ_source_comments_", dir=temp_root
    ) as tmpdir:
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

        clean_failures = MODULE.collect_failures([clean])
        if clean_failures:
            raise SystemExit("expected clean source comment to pass")

        flagged_failures = MODULE.collect_failures([flagged])
        if not flagged_failures:
            raise SystemExit("expected flagged source comment to fail")
        flagged_text = "\n".join(
            "{}:{}:{}:{}".format(path, line_no, rule_name, token)
            for path, findings in flagged_failures
            for line_no, rule_name, token, _guidance in findings
        )
        if "todo_marker" not in flagged_text:
            raise SystemExit("missing todo_marker finding")
        if "hype_without_evidence" not in flagged_text:
            raise SystemExit("missing hype_without_evidence finding")
        if "vague_certainty" not in flagged_text:
            raise SystemExit("missing vague_certainty finding")

        outside_root = Path(tempfile.mkdtemp(prefix="sp_differ_source_comments_outside_"))
        try:
            outside = outside_root / "outside.py"
            outside.write_text("# {} outside repo\n".format("TO" "DO"), encoding="utf-8")
            linked_dir = tmp / "linked"
            linked_dir.mkdir()
            os.symlink(str(outside), str(linked_dir / "outside.py"))

            try:
                MODULE.collect_failures([linked_dir])
            except ValueError as exc:
                if "path escapes repository root" not in str(exc):
                    raise SystemExit("missing repository-root escape failure")
            else:
                raise SystemExit("expected external symlink target to fail")
        finally:
            outside.unlink()
            outside_root.rmdir()

    print("source comment discipline smoke OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
