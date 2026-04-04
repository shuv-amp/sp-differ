#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate a hashed release-evidence manifest from materialized build artifacts."""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

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


def _render_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Release Evidence Manifest",
        "",
        "- generated_at_utc: `{}`".format(report["generated_at_utc"]),
        "- file_count: `{}`".format(len(report["files"])),
        "",
        "This manifest records the exact local evidence files that supported the release-oriented verdict at generation time.",
        "",
        "| Path | Size (bytes) | SHA256 |",
        "| --- | ---: | --- |",
    ]
    for item in report["files"]:
        lines.append(
            "| `{}` | `{}` | `{}` |".format(
                item["path"], item["size_bytes"], item["sha256"]
            )
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a hashed release evidence manifest")
    parser.add_argument(
        "--path",
        dest="paths",
        action="append",
        type=Path,
        required=True,
        help="Evidence file to include; may be specified multiple times",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=Path("build/release_evidence_manifest.json"),
        help="Where to write the JSON manifest",
    )
    parser.add_argument(
        "--markdown-out",
        type=Path,
        help="Optional markdown summary path",
    )
    args = parser.parse_args()

    files: List[Dict[str, Any]] = []
    missing: List[str] = []
    for raw_path in args.paths:
        path = raw_path if raw_path.is_absolute() else Path.cwd() / raw_path
        if not path.exists():
            missing.append(str(raw_path))
            continue
        if not path.is_file():
            raise RuntimeError("{} is not a file".format(raw_path))
        display_path = str(raw_path if raw_path.is_absolute() else raw_path)
        files.append(
            {
                "path": display_path,
                "size_bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
        )

    if missing:
        raise RuntimeError("missing required evidence files: {}".format(", ".join(missing)))

    report = {
        "release_evidence_version": 1,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "files": files,
    }
    write_json(args.json_out, report)
    if args.markdown_out is not None:
        args.markdown_out.write_text(_render_markdown(report) + "\n", encoding="utf-8")

    print("release evidence manifest OK")
    print("  files: {}".format(len(files)))
    print("  wrote report: {}".format(args.json_out))
    if args.markdown_out is not None:
        print("  wrote markdown: {}".format(args.markdown_out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
