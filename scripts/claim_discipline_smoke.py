#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Smoke-test the public claim-discipline checker."""

import importlib.util
import tempfile
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "check_claim_discipline.py"

_SPEC = importlib.util.spec_from_file_location("check_claim_discipline", MODULE_PATH)
assert _SPEC is not None and _SPEC.loader is not None
MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(MODULE)


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

        clean_failures = MODULE.collect_failures([clean])
        if clean_failures:
            raise SystemExit("expected clean file to pass")

        flagged_failures = MODULE.collect_failures([flagged])
        if not flagged_failures:
            raise SystemExit("expected flagged file to fail")
        flagged_text = "\n".join(
            "{}:{}:{}:{}".format(path, finding["line"], finding["rule"], finding["token"])
            for path, findings in flagged_failures
            for finding in findings
        )
        if "unsupported_superlative" not in flagged_text:
            raise SystemExit("missing unsupported_superlative finding")
        if "future_tense_claim" not in flagged_text:
            raise SystemExit("missing future_tense_claim finding")

        outside_root = Path(tempfile.mkdtemp(prefix="sp_differ_claims_outside_"))
        try:
            outside = outside_root / "outside.md"
            outside.write_text("# outside\n\nThis is the best implementation overall.\n", encoding="utf-8")
            linked_dir = tmp / "linked"
            linked_dir.mkdir()
            os.symlink(str(outside), str(linked_dir / "outside.md"))

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

    print("claim discipline smoke OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
