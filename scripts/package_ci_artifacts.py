#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Package CI reports and replay artifacts into a tar archive."""

import argparse
import io
import json
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List


def _normalize_path(path: Path) -> str:
    return path.as_posix().lstrip("./")


def _display_path(raw_path: Path, resolved_path: Path) -> Path:
    if raw_path.is_absolute():
        try:
            return resolved_path.relative_to(Path.cwd())
        except ValueError:
            return raw_path
    return raw_path


def _add_path(
    archive: tarfile.TarFile,
    prefix: str,
    resolved_path: Path,
    display_path: Path,
    included: List[Dict[str, str]],
) -> None:
    arcname = "{}/{}".format(prefix, _normalize_path(display_path))
    archive.add(resolved_path, arcname=arcname, recursive=True)
    included.append(
        {
            "path": str(display_path),
            "type": "directory" if resolved_path.is_dir() else "file",
        }
    )


def _add_manifest(
    archive: tarfile.TarFile,
    prefix: str,
    label: str,
    output: Path,
    included: List[Dict[str, str]],
    missing: List[str],
) -> None:
    payload = {
        "artifact_bundle_version": 1,
        "label": label,
        "output": str(output),
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "included": included,
        "missing": missing,
    }
    manifest_bytes = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    info = tarfile.TarInfo(name="{}/manifest.json".format(prefix))
    info.size = len(manifest_bytes)
    info.mode = 0o644
    archive.addfile(info, io.BytesIO(manifest_bytes))


def main() -> int:
    parser = argparse.ArgumentParser(description="Package CI artifacts into a tar archive")
    parser.add_argument("--label", required=True, help="Top-level directory name inside the tar archive")
    parser.add_argument("--output", type=Path, required=True, help="Tar archive output path")
    parser.add_argument(
        "--path",
        dest="paths",
        action="append",
        required=True,
        type=Path,
        help="File or directory to include; may be specified multiple times",
    )
    args = parser.parse_args()

    included: List[Dict[str, str]] = []
    missing: List[str] = []
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(args.output, mode="w") as archive:
        for raw_path in args.paths:
            resolved_path = raw_path if raw_path.is_absolute() else Path.cwd() / raw_path
            if resolved_path.exists():
                display_path = _display_path(raw_path, resolved_path)
                _add_path(archive, args.label, resolved_path, display_path, included)
            else:
                missing.append(str(raw_path))
        _add_manifest(archive, args.label, args.label, args.output, included, missing)

    print("ci artifact package OK")
    print("  label: {}".format(args.label))
    print("  output: {}".format(args.output))
    print("  included: {}".format(len(included)))
    print("  missing: {}".format(len(missing)))
    for item in missing[:10]:
        print("  - missing: {}".format(item))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
