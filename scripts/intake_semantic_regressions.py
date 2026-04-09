#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Promote semantic failure artifacts into the tracked regression suite."""

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


def _slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _relpath(path: Path, root: Path) -> str:
    return str(path.relative_to(root))


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_manifest(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {"regression_manifest_version": 1, "cases": []}
    return _load_json(path)


@contextlib.contextmanager
def _manifest_lock(manifest_path: Path, timeout_seconds: float = 30.0):
    lock_path = manifest_path.with_suffix(manifest_path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w", encoding="utf-8") as handle:
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        "timed out waiting for manifest lock: {}".format(lock_path)
                    )
                time.sleep(0.05)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _write_manifest(path: Path, manifest: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as handle:
        handle.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    tmp_path.replace(path)


def _copy_if_present(source: Optional[Path], target: Path) -> Optional[str]:
    if source is None or not source.exists():
        return None
    shutil.copyfile(source, target)
    return target.name


def _promote_artifact(
    artifact_dir: Path,
    suite_root: Path,
    manifest_cases: List[Dict[str, Any]],
    force: bool,
    expectation_mode: str,
) -> str:
    summary_path = artifact_dir / "summary.json"
    request_path = artifact_dir / "request.json"
    expected_path = artifact_dir / "expected.json"
    case_path = artifact_dir / "case.hex"
    actual_path = artifact_dir / "actual.json"
    if not summary_path.exists():
        raise RuntimeError("missing summary.json in {}".format(artifact_dir))
    if not request_path.exists():
        raise RuntimeError("missing request.json in {}".format(artifact_dir))
    if not expected_path.exists():
        raise RuntimeError("missing expected.json in {}".format(artifact_dir))

    summary = _load_json(summary_path)
    request = _load_json(request_path)
    expected = _load_json(expected_path)
    actual = _load_json(actual_path) if actual_path.exists() else None
    if expectation_mode == "observed_actual" and actual is None:
        raise RuntimeError(
            "observed_actual expectation mode requires actual.json in {}".format(artifact_dir)
        )
    regression_id = "{}__{}".format(summary["id"], _slugify(summary["adapter_name"]))
    target_dir = suite_root / "cases" / regression_id
    if target_dir.exists() and force:
        shutil.rmtree(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    copied_case = target_dir / "case.hex"
    copied_expected = target_dir / "expected.json"
    copied_request = target_dir / "request.json"
    copied_summary = target_dir / "observed_summary.json"
    copied_actual = target_dir / "observed_actual.json"
    provenance_path = target_dir / "provenance.json"

    if target_dir.exists() and not force and provenance_path.exists():
        existing_provenance = _load_json(provenance_path) if provenance_path.exists() else {}
        if (
            existing_provenance.get("request_sha256") == _sha256(request_path)
            and (
                not case_path.exists()
                or existing_provenance.get("case_sha256") == _sha256(case_path)
            )
        ):
            return regression_id
        raise RuntimeError(
            "regression {} already exists with different contents; use --force".format(
                regression_id
            )
        )

    if case_path.exists():
        shutil.copyfile(case_path, copied_case)
    shutil.copyfile(expected_path, copied_expected)
    shutil.copyfile(request_path, copied_request)
    shutil.copyfile(summary_path, copied_summary)
    _copy_if_present(actual_path if actual is not None else None, copied_actual)

    provenance = {
        "regression_id": regression_id,
        "source_case_id": summary["id"],
        "adapter_name": summary["adapter_name"],
        "kind": request["kind"],
        "source": expected["source"],
        "errors": summary["errors"],
        "captured_from_artifact_dir": str(artifact_dir),
        "repro_cmd": summary["repro_cmd"],
        "request_sha256": _sha256(request_path),
        "case_sha256": _sha256(case_path) if case_path.exists() else None,
        "expected_sha256": _sha256(expected_path),
        "actual_sha256": _sha256(actual_path) if actual is not None else None,
        "expectation_mode": expectation_mode,
    }
    provenance_path.write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    entry = {
        "id": regression_id,
        "source_case_id": summary["id"],
        "adapter_name": summary["adapter_name"],
        "kind": request["kind"],
        "expectation_path": _relpath(copied_expected, suite_root),
        "request_path": _relpath(copied_request, suite_root),
        "observed_summary_path": _relpath(copied_summary, suite_root),
        "provenance_path": _relpath(provenance_path, suite_root),
        "observed_actual_path": None if actual is None else _relpath(copied_actual, suite_root),
        "errors": summary["errors"],
        "source": expected["source"],
        "expectation_mode": expectation_mode,
    }
    if case_path.exists():
        entry["path"] = _relpath(copied_case, suite_root)

    manifest_cases[:] = [item for item in manifest_cases if item.get("id") != regression_id]
    manifest_cases.append(entry)
    manifest_cases.sort(key=lambda item: item["id"])
    return regression_id


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Promote semantic failure artifacts into the tracked regression suite"
    )
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        action="append",
        required=True,
        help="Path to a per-case artifact directory created by run_semantic_adapter_cases.py",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("tests/regressions/semantic/manifest.json"),
        help="Path to the regression manifest to create or update",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing regression directory if the id already exists",
    )
    parser.add_argument(
        "--expectation-mode",
        choices=("oracle", "observed_actual"),
        default="oracle",
        help="Whether the promoted case should compare against the oracle expectation or the observed actual result",
    )
    args = parser.parse_args()

    try:
        with _manifest_lock(args.manifest):
            manifest = _load_manifest(args.manifest)
            cases = manifest.setdefault("cases", [])
            if not isinstance(cases, list):
                raise RuntimeError("manifest cases must be a list")
            manifest["regression_manifest_version"] = 1
            suite_root = args.manifest.parent
            promoted = []
            for artifact_dir in args.artifact_dir:
                promoted.append(
                    _promote_artifact(
                        artifact_dir,
                        suite_root,
                        cases,
                        args.force,
                        args.expectation_mode,
                    )
                )
            _write_manifest(args.manifest, manifest)
    except Exception as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2

    print("semantic regression intake OK")
    print("  manifest: {}".format(args.manifest))
    print("  promoted: {}".format(len(promoted)))
    for regression_id in promoted:
        print("  - {}".format(regression_id))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
