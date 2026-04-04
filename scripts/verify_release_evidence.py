#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify a release-evidence manifest against the current filesystem and optional tag."""

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from bip352_vectors import write_json


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _verify_tag(tag: str) -> Dict[str, Any]:
    completed = subprocess.run(
        ["git", "tag", "-v", tag],
        check=False,
        capture_output=True,
        text=True,
    )
    details = (completed.stdout + completed.stderr).strip()
    if len(details) > 4000:
        details = details[:4000] + "\n...[truncated]..."
    return {
        "tag": tag,
        "status": "passed" if completed.returncode == 0 else "failed",
        "exit_code": completed.returncode,
        "details": details,
    }


def _render_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Release Evidence Verification",
        "",
        "- generated_at_utc: `{}`".format(report["generated_at_utc"]),
        "- manifest: `{}`".format(report["manifest_path"]),
        "- status: `{}`".format(report["status"]),
        "- verified_files: `{}`".format(report["verified_file_count"]),
        "",
    ]

    tag_result = report.get("tag_verification")
    if isinstance(tag_result, dict):
        lines.extend(
            [
                "## Tag Verification",
                "",
                "- tag: `{}`".format(tag_result.get("tag")),
                "- status: `{}`".format(tag_result.get("status")),
                "- exit_code: `{}`".format(tag_result.get("exit_code")),
                "",
            ]
        )

    mismatches = report.get("mismatches", [])
    missing = report.get("missing_files", [])
    if mismatches or missing:
        lines.extend(["## Failures", ""])
        for item in missing:
            lines.append("- missing file: `{}`".format(item))
        for item in mismatches:
            lines.append(
                "- hash/size mismatch: `{}` (expected sha256 `{}`, actual sha256 `{}`)".format(
                    item["path"], item["expected_sha256"], item["actual_sha256"]
                )
            )
        lines.append("")
    else:
        lines.extend(["All manifest files matched current on-disk size and SHA256 values.", ""])

    return "\n".join(lines)


def _load_manifest(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise RuntimeError("manifest must be a JSON object")
    files = data.get("files")
    if not isinstance(files, list) or not files:
        raise RuntimeError("manifest files list is empty")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a release-evidence manifest against current files")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("build/release_evidence_manifest.json"),
        help="Release-evidence manifest JSON path",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=Path("build/release_evidence_verification.json"),
        help="Where to write the machine-readable verification report",
    )
    parser.add_argument(
        "--markdown-out",
        type=Path,
        default=Path("build/release_evidence_verification.md"),
        help="Where to write the markdown verification summary",
    )
    parser.add_argument(
        "--tag",
        type=str,
        help="Optional signed git tag to verify with `git tag -v`",
    )
    parser.add_argument(
        "--require-tag",
        action="store_true",
        help="Fail if `--tag` is not supplied",
    )
    args = parser.parse_args()

    if args.require_tag and not args.tag:
        raise RuntimeError("--require-tag was set but no --tag value was provided")

    manifest = _load_manifest(args.manifest)
    seen_paths = set()
    mismatches: List[Dict[str, Any]] = []
    missing_files: List[str] = []
    verified_file_count = 0

    for item in manifest["files"]:
        if not isinstance(item, dict):
            raise RuntimeError("manifest file entries must be objects")
        raw_path = item.get("path")
        if not isinstance(raw_path, str) or not raw_path:
            raise RuntimeError("manifest file entry is missing a path")
        if raw_path in seen_paths:
            raise RuntimeError("duplicate manifest path: {}".format(raw_path))
        seen_paths.add(raw_path)

        path = Path(raw_path)
        if not path.is_absolute():
            path = Path.cwd() / path
        if not path.exists():
            missing_files.append(raw_path)
            continue
        if not path.is_file():
            raise RuntimeError("{} is not a file".format(raw_path))

        actual_size = path.stat().st_size
        actual_sha256 = _sha256(path)
        expected_size = item.get("size_bytes")
        expected_sha256 = item.get("sha256")
        if actual_size != expected_size or actual_sha256 != expected_sha256:
            mismatches.append(
                {
                    "path": raw_path,
                    "expected_size_bytes": expected_size,
                    "actual_size_bytes": actual_size,
                    "expected_sha256": expected_sha256,
                    "actual_sha256": actual_sha256,
                }
            )
            continue
        verified_file_count += 1

    tag_verification: Optional[Dict[str, Any]] = None
    if args.tag:
        tag_verification = _verify_tag(args.tag)

    status = "passed"
    if missing_files or mismatches:
        status = "failed"
    if tag_verification is not None and tag_verification["status"] != "passed":
        status = "failed"

    report: Dict[str, Any] = {
        "release_evidence_verification_version": 1,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "manifest_path": str(args.manifest),
        "manifest_generated_at_utc": manifest.get("generated_at_utc"),
        "status": status,
        "verified_file_count": verified_file_count,
        "missing_files": missing_files,
        "mismatches": mismatches,
    }
    if tag_verification is not None:
        report["tag_verification"] = tag_verification

    write_json(args.json_out, report)
    args.markdown_out.write_text(_render_markdown(report) + "\n", encoding="utf-8")

    print("release evidence verification {}".format(status))
    print("  manifest: {}".format(args.manifest))
    print("  verified files: {}".format(verified_file_count))
    if missing_files:
        print("  missing files: {}".format(len(missing_files)))
    if mismatches:
        print("  mismatches: {}".format(len(mismatches)))
    if tag_verification is not None:
        print("  tag verification: {}".format(tag_verification["status"]))

    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
