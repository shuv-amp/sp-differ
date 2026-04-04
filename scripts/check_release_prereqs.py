#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify human-owned prerequisites for an official public release."""

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from bip352_vectors import write_json


LICENSE_CANDIDATES = (
    "LICENSE",
    "LICENSE.txt",
    "LICENSE.md",
    "COPYING",
    "UNLICENSE",
)

FINGERPRINT_PATTERN = re.compile(
    r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{40}|(?:[A-Fa-f0-9]{4}\s+){9}[A-Fa-f0-9]{4})(?![A-Fa-f0-9])"
)


def _find_license_files(repo_root: Path) -> List[str]:
    files: List[str] = []
    for name in LICENSE_CANDIDATES:
        candidate = repo_root / name
        if candidate.is_file():
            files.append(name)
    return files


def _extract_fingerprints(security_text: str) -> List[str]:
    values = []
    for match in FINGERPRINT_PATTERN.findall(security_text):
        normalized = "".join(match.split()).upper()
        if normalized not in values:
            values.append(normalized)
    return values


def _render_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Release Prerequisites",
        "",
        "- generated_at_utc: `{}`".format(report["generated_at_utc"]),
        "- repo_root: `{}`".format(report["repo_root"]),
        "- status: `{}`".format(report["status"]),
        "",
        "## Checks",
        "",
    ]

    for check in report["checks"]:
        lines.append(
            "- {}: `{}` ({})".format(check["name"], check["status"], check["detail"])
        )
    lines.append("")

    if report["missing"]:
        lines.extend(["## Missing", ""])
        for item in report["missing"]:
            lines.append("- `{}`".format(item))
        lines.append("")

    if report["license_files"]:
        lines.extend(["## License Files", ""])
        for path in report["license_files"]:
            lines.append("- `{}`".format(path))
        lines.append("")

    if report["maintainer_signing_fingerprints"]:
        lines.extend(["## Maintainer Signing Fingerprints", ""])
        for fingerprint in report["maintainer_signing_fingerprints"]:
            lines.append("- `{}`".format(fingerprint))
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify human-owned prerequisites for an official public release"
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Repository root to audit",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=Path("build/release_prereqs.json"),
        help="Where to write the machine-readable report",
    )
    parser.add_argument(
        "--markdown-out",
        type=Path,
        default=Path("build/release_prereqs.md"),
        help="Where to write the markdown report",
    )
    args = parser.parse_args()

    repo_root = args.repo_root.resolve()
    security_path = repo_root / "SECURITY.md"
    checks: List[Dict[str, str]] = []
    missing: List[str] = []

    license_files = _find_license_files(repo_root)
    if license_files:
        checks.append(
            {
                "name": "top_level_license",
                "status": "passed",
                "detail": "found {} top-level license file(s)".format(len(license_files)),
            }
        )
    else:
        checks.append(
            {
                "name": "top_level_license",
                "status": "failed",
                "detail": "no repository-wide top-level license file was found",
            }
        )
        missing.append("top-level LICENSE file")

    security_text = ""
    if security_path.is_file():
        security_text = security_path.read_text(encoding="utf-8")
        checks.append(
            {
                "name": "security_policy",
                "status": "passed",
                "detail": "found SECURITY.md",
            }
        )
    else:
        checks.append(
            {
                "name": "security_policy",
                "status": "failed",
                "detail": "SECURITY.md is missing",
            }
        )
        missing.append("SECURITY.md")

    fingerprints = _extract_fingerprints(security_text) if security_text else []
    if fingerprints:
        checks.append(
            {
                "name": "maintainer_signing_fingerprints",
                "status": "passed",
                "detail": "found {} maintainer signing fingerprint(s)".format(
                    len(fingerprints)
                ),
            }
        )
    else:
        checks.append(
            {
                "name": "maintainer_signing_fingerprints",
                "status": "failed",
                "detail": "no maintainer signing fingerprint is published in SECURITY.md",
            }
        )
        missing.append("published maintainer signing fingerprint in SECURITY.md")

    status = "passed" if not missing else "failed"
    report: Dict[str, Any] = {
        "release_prereq_version": 1,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "repo_root": str(repo_root),
        "status": status,
        "checks": checks,
        "missing": missing,
        "license_files": license_files,
        "maintainer_signing_fingerprints": fingerprints,
    }

    write_json(args.json_out, report)
    args.markdown_out.write_text(_render_markdown(report) + "\n", encoding="utf-8")

    print("release prereqs {}".format(status))
    if missing:
        print("  missing: {}".format(", ".join(missing)))
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
