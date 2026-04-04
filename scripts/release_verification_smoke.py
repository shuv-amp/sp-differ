#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Smoke-test release-evidence verification."""

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
    with tempfile.TemporaryDirectory(prefix="sp_differ_release_verify_") as tmpdir:
        tmp = Path(tmpdir)
        build_dir = tmp / "build"
        build_dir.mkdir()
        evidence_a = build_dir / "a.json"
        evidence_b = build_dir / "b.md"
        evidence_a.write_text('{"status":"passed"}\n', encoding="utf-8")
        evidence_b.write_text("# Summary\n", encoding="utf-8")

        manifest = build_dir / "release_evidence_manifest.json"
        manifest_md = build_dir / "release_evidence_manifest.md"
        generated = _run(
            [
                str(repo_root / "scripts" / "generate_release_evidence_manifest.py"),
                "--json-out",
                str(manifest),
                "--markdown-out",
                str(manifest_md),
                "--path",
                str(evidence_a),
                "--path",
                str(evidence_b),
            ],
            cwd=repo_root,
        )
        if generated.returncode != 0:
            raise SystemExit("failed to generate manifest:\n{}".format(generated.stdout + generated.stderr))

        verified = _run(
            [
                str(repo_root / "scripts" / "verify_release_evidence.py"),
                "--manifest",
                str(manifest),
                "--json-out",
                str(build_dir / "release_evidence_verification.json"),
                "--markdown-out",
                str(build_dir / "release_evidence_verification.md"),
            ],
            cwd=repo_root,
        )
        if verified.returncode != 0:
            raise SystemExit("expected verification to pass:\n{}".format(verified.stdout + verified.stderr))

        evidence_a.write_text('{"status":"failed"}\n', encoding="utf-8")
        drifted = _run(
            [
                str(repo_root / "scripts" / "verify_release_evidence.py"),
                "--manifest",
                str(manifest),
                "--json-out",
                str(build_dir / "release_evidence_verification_failed.json"),
                "--markdown-out",
                str(build_dir / "release_evidence_verification_failed.md"),
            ],
            cwd=repo_root,
        )
        if drifted.returncode == 0:
            raise SystemExit("expected drifted verification to fail")
        if "mismatches: 1" not in drifted.stdout:
            raise SystemExit("expected mismatch count in drifted verification output")

    print("release verification smoke OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
