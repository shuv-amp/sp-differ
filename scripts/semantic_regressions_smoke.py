#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Smoke tests for request-backed and adapter-scoped semantic regressions."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run_semantic_regressions.py"
REAL_MANIFEST = ROOT / "tests" / "regressions" / "semantic" / "manifest.json"


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


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
            "comment": "semantic regression smoke",
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
            }
        ],
    }


def _send_result(
    source_id: str,
    notes: list[str],
    semantic_status: str = "no_eligible_inputs",
    input_private_key_sum=None,
) -> dict:
    return {
        "semantic_contract_version": 1,
        "case_format_version": 2,
        "kind": "send",
        "source": {
            "case_index": 0,
            "comment": "semantic regression smoke",
            "entry_index": 0,
            "id": source_id,
            "kind": "send",
        },
        "semantic_status": semantic_status,
        "input_pubkeys": [],
        "input_hash": None,
        "input_private_key_sum": input_private_key_sum,
        "sender_shared_secrets": [
            {
                "scan_pubkey": "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                "shared_secret": None,
            }
        ],
        "acceptable_output_sets": [[]],
        "output_count_options": [0],
        "notes": notes,
    }


def _write_adapter(path: Path) -> None:
    path.write_text(
        """#!/usr/bin/env python3
import json
import os
import sys

request = json.load(sys.stdin)
source_id = request["source"]["id"]

GLOBAL = {
    "semantic_contract_version": 1,
    "case_format_version": 2,
    "kind": "send",
    "source": request["source"],
    "semantic_status": "no_eligible_inputs",
    "input_pubkeys": [],
    "input_hash": None,
    "input_private_key_sum": None,
    "sender_shared_secrets": [
        {
            "scan_pubkey": request["recipient_groups"][0]["scan_pubkey"],
            "shared_secret": None,
        }
    ],
    "acceptable_output_sets": [[]],
    "output_count_options": [0],
    "notes": [],
}

DIVERGENCE = dict(GLOBAL)
DIVERGENCE["source"] = request["source"]
DIVERGENCE["semantic_status"] = "zero_scalar"
DIVERGENCE["input_private_key_sum"] = "0000000000000000000000000000000000000000000000000000000000000000"
DIVERGENCE["notes"] = []

mode = os.environ.get("SP_DIFFER_SMOKE_MODE", "observed")
if source_id == "request_only_global":
    payload = GLOBAL
elif source_id == "request_only_divergence":
    payload = GLOBAL if mode == "oracle" else DIVERGENCE
else:
    raise SystemExit("unknown source id: " + source_id)

json.dump(payload, sys.stdout, sort_keys=True)
sys.stdout.write("\\n")
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


def _run(manifest: Path, adapter_name: str, adapter_path: Path, mode: str, out_dir: Path) -> tuple[int, dict]:
    json_out = out_dir / "{}.json".format(adapter_name.replace("-", "_"))
    markdown_out = out_dir / "{}.md".format(adapter_name.replace("-", "_"))
    env = dict(os.environ)
    env["SP_DIFFER_SMOKE_MODE"] = mode
    proc = subprocess.run(
        [
            sys.executable,
            str(RUNNER),
            "--adapter-name",
            adapter_name,
            "--adapter-cmd",
            str(adapter_path),
            "--manifest",
            str(manifest),
            "--json-out",
            str(json_out),
            "--markdown-out",
            str(markdown_out),
        ],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    payload = json.loads(json_out.read_text(encoding="utf-8"))
    return proc.returncode, payload


def main() -> int:
    real_manifest = json.loads(REAL_MANIFEST.read_text(encoding="utf-8"))
    real_cases = real_manifest.get("cases", [])
    global_repeated_key = [
        item
        for item in real_cases
        if item.get("id") == "official_case_25_send_00__repeated_key_unique_outpoint"
    ]
    _require(len(global_repeated_key) == 1, "expected one global repeated-key regression entry")
    _require(
        global_repeated_key[0].get("adapter_names")
        == [
            "reference",
            "go-bip352",
            "go-bip352-ffi",
            "bitcoin-core-exp",
        ],
        "expected repeated-key oracle case to stay scoped to the known passing adapters",
    )

    with tempfile.TemporaryDirectory(prefix="sp_differ_semantic_regressions_") as tmp:
        tmp_root = Path(tmp)
        manifest = tmp_root / "tests" / "regressions" / "semantic" / "manifest.json"
        adapter = tmp_root / "adapter.py"
        reports = tmp_root / "reports"
        reports.mkdir(parents=True, exist_ok=True)

        global_request = _send_request("request_only_global")
        divergence_request = _send_request("request_only_divergence")
        global_expected = _send_result("request_only_global", [])
        divergence_expected = _send_result("request_only_divergence", [])
        divergence_observed = _send_result(
            "request_only_divergence",
            [],
            semantic_status="zero_scalar",
            input_private_key_sum="0000000000000000000000000000000000000000000000000000000000000000",
        )

        _write_json(
            tmp_root / "tests" / "regressions" / "semantic" / "cases" / "request_only_global" / "request.json",
            global_request,
        )
        _write_json(
            tmp_root / "tests" / "regressions" / "semantic" / "cases" / "request_only_global" / "expected.json",
            global_expected,
        )
        _write_json(
            tmp_root / "tests" / "regressions" / "semantic" / "cases" / "request_only_divergence" / "request.json",
            divergence_request,
        )
        _write_json(
            tmp_root / "tests" / "regressions" / "semantic" / "cases" / "request_only_divergence" / "expected.json",
            divergence_expected,
        )
        _write_json(
            tmp_root / "tests" / "regressions" / "semantic" / "cases" / "request_only_divergence" / "observed_actual.json",
            divergence_observed,
        )
        _write_json(
            manifest,
            {
                "regression_manifest_version": 1,
                "cases": [
                    {
                        "id": "request_only_global",
                        "kind": "send",
                        "path": "cases/request_only_global/does_not_exist.hex",
                        "request_path": "cases/request_only_global/request.json",
                        "expectation_path": "cases/request_only_global/expected.json",
                        "source": global_expected["source"],
                    },
                    {
                        "id": "request_only_divergence__smoke_target",
                        "kind": "send",
                        "adapter_name": "smoke-target",
                        "request_path": "cases/request_only_divergence/request.json",
                        "expectation_path": "cases/request_only_divergence/expected.json",
                        "observed_actual_path": "cases/request_only_divergence/observed_actual.json",
                        "expectation_mode": "observed_actual",
                        "errors": [
                            "field mismatch: semantic_status",
                            "field mismatch: input_private_key_sum",
                        ],
                        "source": divergence_expected["source"],
                    },
                ],
            },
        )
        _write_adapter(adapter)

        rc, payload = _run(manifest, "smoke-target", adapter, "observed", reports)
        _require(rc == 0, "expected targeted regression run to pass")
        _require(payload["derived_case_count"] == 2, "expected two selected cases for smoke-target")
        _require(payload["skipped_case_count"] == 0, "expected zero skipped cases for smoke-target")

        rc, payload = _run(manifest, "smoke-other", adapter, "observed", reports)
        _require(rc == 0, "expected non-targeted regression run to pass")
        _require(payload["derived_case_count"] == 1, "expected only global case for smoke-other")
        _require(payload["skipped_case_count"] == 1, "expected one skipped adapter-scoped case")

        rc, payload = _run(manifest, "smoke-target", adapter, "oracle", reports)
        _require(rc == 2, "expected resolved known divergence to fail the smoke run")
        _require(payload["failed_case_count"] == 1, "expected one failure when divergence disappears")
        _require(
            "tracked divergence no longer reproduces" in payload["failures"][0]["errors"][0],
            "expected a resolved-divergence failure message",
        )

    print("semantic regressions smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
