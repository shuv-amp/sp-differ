#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Smoke test for semantic adapter fuzz minimization and regression bundles."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run_semantic_adapter_fuzz.py"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _send_request(source_id: str) -> dict:
    return {
        "semantic_adapter_request_version": 1,
        "case_format_version": 2,
        "kind": "send",
        "network": "mainnet",
        "silent_payment_version": 0,
        "seed": 0,
        "flags": 0,
        "source": {
            "case_index": 0,
            "comment": "semantic adapter fuzz smoke",
            "entry_index": 0,
            "id": source_id,
            "kind": "send",
        },
        "inputs": [],
        "recipient_groups": [
            {
                "scan_pubkey": "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                "spend_pubkey": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "count": 1,
            },
            {
                "scan_pubkey": "02f9308a019258c3106f8bf3f6eb5f6cc2f6f55e3a0f7ec7a4b0d9f8e0f44cfa14",
                "spend_pubkey": "02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
                "count": 2,
            },
        ],
    }


def _write_adapter(path: Path) -> None:
    path.write_text(
        """#!/usr/bin/env python3
import json
import sys

request = json.load(sys.stdin)
payload = {
    "semantic_contract_version": 1,
    "case_format_version": 2,
    "kind": "send",
    "source": request["source"],
    "semantic_status": "zero_scalar",
    "input_pubkeys": [],
    "input_hash": None,
    "input_private_key_sum": "0000000000000000000000000000000000000000000000000000000000000000",
    "sender_shared_secrets": [
        {
            "scan_pubkey": group["scan_pubkey"],
            "shared_secret": None,
        }
        for group in request["recipient_groups"]
    ],
    "acceptable_output_sets": [[]],
    "output_count_options": [0],
    "notes": [],
}
json.dump(payload, sys.stdout, sort_keys=True)
sys.stdout.write("\\n")
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="sp_differ_semantic_adapter_fuzz_") as tmp:
        tmp_root = Path(tmp)
        corpus_root = tmp_root / "corpus"
        adapter_path = tmp_root / "adapter.py"
        request_path = corpus_root / "valid" / "seed_case.json"
        report_path = tmp_root / "report.json"
        markdown_path = tmp_root / "report.md"
        artifact_dir = tmp_root / "artifacts"

        _write_json(
            corpus_root / "manifest.json",
            {
                "semantic_worker_corpus_version": 1,
                "generated_from": [],
                "valid": [
                    {
                        "id": "seed_case",
                        "kind": "send",
                        "path": "valid/seed_case.json",
                        "source": "smoke",
                        "source_case_path": "tests/vectors/smoke.hex",
                    }
                ],
                "invalid": [],
            },
        )
        _write_json(request_path, _send_request("seed_case"))
        _write_adapter(adapter_path)

        proc = subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                "--adapter-name",
                "smoke-adapter",
                "--adapter-cmd",
                str(adapter_path),
                "--corpus-root",
                str(corpus_root),
                "--seed",
                "352",
                "--iterations",
                "0",
                "--max-failures",
                "1",
                "--json-out",
                str(report_path),
                "--markdown-out",
                str(markdown_path),
                "--artifact-dir",
                str(artifact_dir),
            ],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        _require(proc.returncode == 2, "expected fuzz smoke mismatch to fail")

        report = json.loads(report_path.read_text(encoding="utf-8"))
        _require(report["failure_count"] == 1, "expected one fuzz failure")
        failure = report["failures"][0]
        minimization = failure.get("minimization")
        _require(isinstance(minimization, dict), "expected minimization metadata in report")
        _require(
            minimization["minimized_payload_bytes"] < len(json.dumps(_send_request("seed_case"), sort_keys=True)) + 1,
            "expected minimization to reduce the request",
        )

        failure_root = Path(failure["artifact_dir"])
        minimized_dir = failure_root / "minimized"
        bundle_dir = minimized_dir / "regression_bundle"
        _require((minimized_dir / "request.json").exists(), "expected minimized request.json")
        _require((minimized_dir / "summary.json").exists(), "expected minimized summary.json")
        _require((minimized_dir / "replay.sh").exists(), "expected minimized replay script")
        _require((minimized_dir / "promote.sh").exists(), "expected minimized promote script")
        _require(bundle_dir.exists(), "expected regression bundle directory")
        _require((bundle_dir / "request.json").exists(), "expected bundled request.json")
        _require((bundle_dir / "expected.json").exists(), "expected bundled expected.json")
        _require((bundle_dir / "actual.json").exists(), "expected bundled actual.json")
        _require((bundle_dir / "case.hex").exists(), "expected bundled case.hex")

        bundle_summary = json.loads((bundle_dir / "summary.json").read_text(encoding="utf-8"))
        _require(
            bundle_summary["id"] == "seed_case__fuzz_0000",
            "expected descriptive regression bundle id",
        )

    print("semantic adapter fuzz smoke OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
