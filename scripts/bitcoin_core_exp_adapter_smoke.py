#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Smoke tests for the experimental Bitcoin Core semantic adapter wrapper."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from bip352_reference import load_reference_module
from bip352_semantics import derive_receive_semantics, derive_sender_semantics
from semantic_adapter import build_semantic_request
from semantic_case_runner import read_case_v2


ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "adapters" / "bitcoin_core_exp" / "semantic_adapter.py"
REFERENCE = ROOT / "tests" / "vectors" / "bip352" / "official" / "reference" / "reference.py"
REFERENCE_DIR = ROOT / "tests" / "vectors" / "bip352" / "official" / "reference"
SEND_CASE = ROOT / "tests" / "vectors" / "bip352" / "derived" / "v2" / "official_case_00_send_00.hex"
SEND_EXPECTED = ROOT / "tests" / "vectors" / "bip352" / "derived" / "v2" / "official_case_00_send_00.expected.json"
RECEIVE_CASE = ROOT / "tests" / "vectors" / "bip352" / "derived" / "v2" / "official_case_00_receive_00.hex"
RECEIVE_EXPECTED = ROOT / "tests" / "vectors" / "bip352" / "derived" / "v2" / "official_case_00_receive_00.expected.json"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _make_request(case_path: Path, expectation_path: Path) -> dict:
    expected = json.loads(expectation_path.read_text(encoding="utf-8"))
    expectation_hints = {}
    if expected["kind"] == "receive":
        expectation_hints = {
            "detailed_outputs_required": bool(expected.get("detailed_outputs_available", True))
        }
    return build_semantic_request(
        expected["kind"],
        read_case_v2(case_path),
        expected["source"],
        expectation_hints=expectation_hints,
    )


def _run_adapter(helper: Path, request: dict, mode: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["SP_DIFFER_BITCOIN_CORE_SMOKE_MODE"] = mode
    return subprocess.run(
        [sys.executable, str(ADAPTER), "--core-helper", str(helper)],
        cwd=ROOT,
        env=env,
        input=json.dumps(request, sort_keys=True),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def main() -> int:
    reference_module = load_reference_module(REFERENCE, REFERENCE_DIR)
    send_request = _make_request(SEND_CASE, SEND_EXPECTED)
    receive_request = _make_request(RECEIVE_CASE, RECEIVE_EXPECTED)
    send_reference = derive_sender_semantics(
        reference_module, read_case_v2(SEND_CASE), send_request["source"]
    )
    receive_reference = derive_receive_semantics(
        reference_module,
        read_case_v2(RECEIVE_CASE),
        receive_request["source"],
        detailed_outputs_available=True,
    )

    with tempfile.TemporaryDirectory(prefix="sp_differ_bitcoin_core_adapter_") as tmp_dir:
        tmp_root = Path(tmp_dir)
        helper = tmp_root / "fake_helper.py"
        helper.write_text(
            """#!/usr/bin/env python3
import json
import os
import sys

request = json.load(sys.stdin)
mode = os.environ.get("SP_DIFFER_BITCOIN_CORE_SMOKE_MODE", "")
if mode == "send_ok":
    payload = {
        "kind": "send",
        "semantic_status": "ok",
        "outputs": request["expectation_hints"]["smoke_send_outputs"],
    }
elif mode == "send_zero_scalar":
    payload = {
        "kind": "send",
        "semantic_status": "zero_scalar",
        "outputs": [],
    }
elif mode == "receive_ok":
    payload = {
        "kind": "receive",
        "semantic_status": "ok",
        "detailed_outputs_available": True,
        "found_output_count": len(request["expectation_hints"]["smoke_receive_outputs"]),
        "found_outputs": request["expectation_hints"]["smoke_receive_outputs"],
    }
elif mode == "bad_json":
    sys.stdout.write("{bad json")
    sys.exit(0)
else:
    raise SystemExit("unknown mode")

json.dump(payload, sys.stdout, sort_keys=True)
sys.stdout.write("\\n")
""",
            encoding="utf-8",
        )
        helper.chmod(0o755)

        send_request["expectation_hints"]["smoke_send_outputs"] = send_reference["acceptable_output_sets"][0]
        receive_request["expectation_hints"]["smoke_receive_outputs"] = receive_reference["found_outputs"]

        send_ok = _run_adapter(helper, send_request, "send_ok")
        _require(send_ok.returncode == 0, "expected send ok mode to pass")
        send_ok_payload = json.loads(send_ok.stdout)
        _require(send_ok_payload["semantic_status"] == "ok", "expected send ok semantic_status")
        _require(
            send_ok_payload["acceptable_output_sets"] == [send_reference["acceptable_output_sets"][0]],
            "expected send ok outputs to round-trip",
        )

        send_zero = _run_adapter(helper, send_request, "send_zero_scalar")
        _require(send_zero.returncode == 0, "expected send zero-scalar mode to pass")
        send_zero_payload = json.loads(send_zero.stdout)
        _require(
            send_zero_payload["semantic_status"] == "zero_scalar",
            "expected zero-scalar semantic status",
        )
        _require(
            send_zero_payload["acceptable_output_sets"] == [[]],
            "expected non-ok send status to normalize to empty outputs",
        )

        receive_ok = _run_adapter(helper, receive_request, "receive_ok")
        _require(receive_ok.returncode == 0, "expected receive ok mode to pass")
        receive_ok_payload = json.loads(receive_ok.stdout)
        _require(receive_ok_payload["semantic_status"] == "ok", "expected receive ok semantic_status")
        _require(
            receive_ok_payload["found_outputs"] == receive_reference["found_outputs"],
            "expected detailed receive outputs to round-trip",
        )

        bad_json = _run_adapter(helper, send_request, "bad_json")
        _require(bad_json.returncode == 2, "expected malformed helper JSON to fail")
        _require("invalid JSON" in bad_json.stderr, "expected invalid JSON error")

    print("bitcoin core experimental adapter smoke OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
