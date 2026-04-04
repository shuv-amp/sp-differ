#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Smoke test for concurrent semantic regression intake updates."""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict

ROOT = Path(__file__).resolve().parents[1]
INTAKE = ROOT / "scripts" / "intake_semantic_regressions.py"


def _write_json(path: Path, payload: Dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _create_artifact(root: Path, index: int) -> Path:
    artifact_dir = root / "artifacts" / "case_{:02d}".format(index)
    artifact_dir.mkdir(parents=True, exist_ok=True)

    case_id = "seed_case_{:02d}".format(index)
    adapter_name = "adapter_{:02d}".format(index)
    regression_id = "{}__{}".format(case_id, adapter_name)

    _write_json(
        artifact_dir / "summary.json",
        {
            "id": case_id,
            "adapter_name": adapter_name,
            "errors": ["synthetic failure {}".format(index)],
            "repro_cmd": "python3 scripts/repro.py --case {}".format(case_id),
        },
    )
    _write_json(artifact_dir / "request.json", {"kind": "send"})
    _write_json(artifact_dir / "expected.json", {"source": "corpus"})
    _write_json(artifact_dir / "actual.json", {"semantic_status": "ok"})
    (artifact_dir / "case.hex").write_text("00\n", encoding="ascii")

    expected_dir = root / "tests" / "regressions" / "semantic" / "cases" / regression_id
    if expected_dir.exists():
        shutil.rmtree(expected_dir)

    return artifact_dir


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="sp_differ_intake_smoke_") as tmp:
        tmp_root = Path(tmp)
        manifest_path = tmp_root / "tests" / "regressions" / "semantic" / "manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)

        artifact_a = _create_artifact(tmp_root, 1)
        artifact_b = _create_artifact(tmp_root, 2)

        cmd_a = [
            sys.executable,
            str(INTAKE),
            "--manifest",
            str(manifest_path),
            "--artifact-dir",
            str(artifact_a),
        ]
        cmd_b = [
            sys.executable,
            str(INTAKE),
            "--manifest",
            str(manifest_path),
            "--artifact-dir",
            str(artifact_b),
        ]

        proc_a = subprocess.Popen(cmd_a, cwd=ROOT)
        proc_b = subprocess.Popen(cmd_b, cwd=ROOT)
        rc_a = proc_a.wait(timeout=30)
        rc_b = proc_b.wait(timeout=30)
        if rc_a != 0 or rc_b != 0:
            print("intake smoke failed: subprocess exit codes {}, {}".format(rc_a, rc_b), file=sys.stderr)
            return 2

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        cases = manifest.get("cases", [])
        ids = sorted(item.get("id") for item in cases)

        expected_ids = ["seed_case_01__adapter_01", "seed_case_02__adapter_02"]
        if ids != expected_ids:
            print("intake smoke failed: expected ids {} got {}".format(expected_ids, ids), file=sys.stderr)
            return 2

        for regression_id in expected_ids:
            case_hex_path = manifest_path.parent / "cases" / regression_id / "case.hex"
            if not case_hex_path.exists():
                print("intake smoke failed: missing promoted artifact {}".format(case_hex_path), file=sys.stderr)
                return 2

    print("semantic intake concurrency smoke OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
