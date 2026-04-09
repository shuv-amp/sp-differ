#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Smoke test for heuristic semantic fuzz introspection."""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INTROSPECTOR = ROOT / "scripts" / "semantic_fuzz_introspector.py"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="sp_differ_semantic_fuzz_introspector_") as tmp:
        tmp_root = Path(tmp)
        corpus_root = tmp_root / "corpus"
        valid_dir = corpus_root / "valid"
        valid_dir.mkdir(parents=True, exist_ok=True)

        source_send = ROOT / "fuzz" / "corpus" / "semantic_worker" / "valid" / "official_case_00_send_00.json"
        source_receive = ROOT / "fuzz" / "corpus" / "semantic_worker" / "valid" / "official_case_00_receive_00.json"
        shutil.copyfile(source_send, valid_dir / "seed_send.json")
        shutil.copyfile(source_receive, valid_dir / "seed_receive.json")

        derived_manifest = tmp_root / "derived_manifest.json"
        regression_manifest = tmp_root / "regression_manifest.json"
        error_surface_manifest = tmp_root / "error_surface_manifest.json"
        report_path = tmp_root / "report.json"
        markdown_path = tmp_root / "report.md"

        _write_json(
            corpus_root / "manifest.json",
            {
                "semantic_worker_corpus_version": 1,
                "generated_from": {
                    "derived_manifest": str(derived_manifest.relative_to(ROOT))
                    if str(tmp_root).startswith(str(ROOT))
                    else str(derived_manifest),
                    "regression_manifest": str(regression_manifest.relative_to(ROOT))
                    if str(tmp_root).startswith(str(ROOT))
                    else str(regression_manifest),
                },
                "valid": [
                    {
                        "id": "seed_send",
                        "kind": "send",
                        "path": "valid/seed_send.json",
                        "source": "smoke",
                    },
                    {
                        "id": "seed_receive",
                        "kind": "receive",
                        "path": "valid/seed_receive.json",
                        "source": "smoke",
                    },
                ],
                "invalid": [],
            },
        )
        _write_json(
            derived_manifest,
            {
                "cases": [
                    {"id": "seed_send"},
                    {"id": "seed_receive"},
                    {"id": "missing_seed"},
                ]
            },
        )
        _write_json(
            regression_manifest,
            {
                "cases": [
                    {"id": "regression_only_seed"},
                ]
            },
        )
        _write_json(
            error_surface_manifest,
            {
                "semantic_error_surface_version": 1,
                "cases": [
                    {
                        "id": "synthetic_invalid_input",
                        "kind": "send",
                        "semantic_status": "invalid_input",
                        "path": "cases/invalid_input.json",
                    }
                ],
                "byte_worker_cases": [],
            },
        )

        proc = subprocess.run(
            [
                sys.executable,
                str(INTROSPECTOR),
                "--corpus-root",
                str(corpus_root),
                "--derived-manifest",
                str(derived_manifest),
                "--regression-manifest",
                str(regression_manifest),
                "--error-surface-manifest",
                str(error_surface_manifest),
                "--json-out",
                str(report_path),
                "--markdown-out",
                str(markdown_path),
                "--top-paths",
                "4",
            ],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        _require(proc.returncode == 0, "expected introspector smoke to pass")

        report = json.loads(report_path.read_text(encoding="utf-8"))
        _require(report["valid_seed_count"] == 2, "expected two valid seeds in introspector report")
        _require(
            report["tracked_universe"]["missing_seed_ids"] == ["missing_seed", "regression_only_seed"],
            "expected tracked-universe drift to be reported",
        )
        _require(
            any(
                gap["dimension"] == "silent_payment_version"
                and gap["missing_value"] == "nonzero"
                for gap in report["gap_candidates"]
            ),
            "expected nonzero silent payment version gap candidate",
        )
        _require(
            "invalid_input" in report["error_surface"]["covered_statuses"],
            "expected separate error-surface coverage to be reported",
        )
        _require(
            not any(
                gap["dimension"] == "semantic_status" and gap["missing_value"] == "invalid_input"
                for gap in report["gap_candidates"]
            ),
            "expected invalid_input to be suppressed by the separate error-surface manifest",
        )
        _require(report["top_path_signatures"], "expected top path signatures in report")

    print("semantic fuzz introspector smoke OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
