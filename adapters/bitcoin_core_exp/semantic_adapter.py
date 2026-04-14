#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Experimental Bitcoin Core semantic adapter backed by a local helper binary."""

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from bip352_reference import load_reference_module  # noqa: E402
from bip352_semantics import derive_receive_semantics, derive_sender_semantics  # noqa: E402
from semantic_adapter import case_from_semantic_request, validate_semantic_request  # noqa: E402
from semantic_contract import normalize_semantic_result, validate_semantic_result  # noqa: E402


def _run_core_helper(helper: Path, request: Dict[str, Any]) -> Dict[str, Any]:
    if not helper.exists():
        raise RuntimeError("core helper does not exist: {}".format(helper))
    if helper.name.startswith("-"):
        raise RuntimeError("refusing helper path that starts with '-': {}".format(helper))

    proc = subprocess.run(
        [str(helper)],
        input=json.dumps(request, sort_keys=True).encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "core helper exited with status {}: {}".format(
                proc.returncode, proc.stderr.decode("utf-8", errors="replace").strip()
            )
        )
    try:
        decoded = json.loads(proc.stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError("core helper returned invalid JSON: {}".format(exc))
    if not isinstance(decoded, dict):
        raise RuntimeError("core helper returned non-object JSON")
    return decoded


def _compose_send_result(
    reference_result: Dict[str, Any], helper_result: Dict[str, Any]
) -> Dict[str, Any]:
    result = dict(reference_result)
    status = helper_result["semantic_status"]
    result["semantic_status"] = status
    if status == "ok":
        outputs = helper_result.get("outputs", [])
        result["acceptable_output_sets"] = [outputs]
        result["output_count_options"] = [len(outputs)]
    else:
        result["acceptable_output_sets"] = [[]]
        result["output_count_options"] = [0]
    return normalize_semantic_result(result)


def _compose_receive_result(
    reference_result: Dict[str, Any], helper_result: Dict[str, Any]
) -> Dict[str, Any]:
    result = dict(reference_result)
    result["semantic_status"] = helper_result["semantic_status"]
    result["detailed_outputs_available"] = bool(
        helper_result.get("detailed_outputs_available", True)
    )
    result["found_outputs"] = helper_result.get("found_outputs", [])
    result["found_output_count"] = int(
        helper_result.get("found_output_count", len(result["found_outputs"]))
    )
    return normalize_semantic_result(result)


def main() -> int:
    parser = argparse.ArgumentParser(description="Experimental Bitcoin Core semantic adapter")
    parser.add_argument(
        "--core-helper",
        type=Path,
        required=True,
        help="Path to the compiled bitcoin_sp_semantic_helper binary",
    )
    args = parser.parse_args()

    try:
        request = validate_semantic_request(json.load(sys.stdin))
        reference_module = load_reference_module(
            REPO_ROOT / "tests/vectors/bip352/official/reference/reference.py",
            REPO_ROOT / "tests/vectors/bip352/official/reference",
        )
        case = case_from_semantic_request(request)
        helper_result = _run_core_helper(args.core_helper.resolve(), request)
        if request["kind"] == "send":
            reference_result = derive_sender_semantics(reference_module, case, request["source"])
            output = _compose_send_result(reference_result, helper_result)
        else:
            reference_result = derive_receive_semantics(
                reference_module,
                case,
                request["source"],
                detailed_outputs_available=True,
                network=request["network"],
            )
            output = _compose_receive_result(reference_result, helper_result)
        json.dump(validate_semantic_result(output), sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
        return 0
    except Exception as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
