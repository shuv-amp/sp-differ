#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Smoke tests for semantic fuzz minimization helpers."""

from semantic_adapter import validate_semantic_request
from semantic_fuzz_minimizer import minimize_raw_payload, minimize_structured_request


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _send_request() -> dict:
    return validate_semantic_request(
        {
            "semantic_adapter_request_version": 1,
            "case_format_version": 2,
            "kind": "send",
            "network": "testnet",
            "silent_payment_version": 3,
            "seed": 99,
            "flags": 511,
            "source": {
                "kind": "send",
                "comment": "synthetic minimizer smoke",
                "case_index": 0,
                "entry_index": 0,
                "id": "synthetic_send_smoke",
            },
            "inputs": [
                {
                    "outpoint_txid": "11" * 32,
                    "outpoint_vout": 7,
                    "input_type": "p2pkh",
                    "prevout_script_pubkey": "51",
                    "script_sig": "4730440220",
                    "txinwitness": "0200",
                    "txinwitness_stack": ["00"],
                    "privkey": "22" * 32,
                    "pubkey": "02" + ("33" * 32),
                },
                {
                    "outpoint_txid": "44" * 32,
                    "outpoint_vout": 3,
                    "input_type": "p2wpkh",
                    "prevout_script_pubkey": "0014" + ("55" * 20),
                    "script_sig": "160014",
                    "txinwitness": "020101",
                    "txinwitness_stack": ["01", "01"],
                    "privkey": "66" * 32,
                    "pubkey": "03" + ("77" * 32),
                },
            ],
            "recipient_groups": [
                {
                    "scan_pubkey": "02" + ("88" * 32),
                    "spend_pubkey": "03" + ("99" * 32),
                    "count": 3,
                },
                {
                    "scan_pubkey": "02" + ("aa" * 32),
                    "spend_pubkey": "03" + ("bb" * 32),
                    "count": 1,
                },
            ],
        }
    )


def _structured_predicate(request: dict):
    if request["kind"] != "send":
        return None
    if len(request["inputs"]) < 1 or len(request["recipient_groups"]) < 1:
        return None
    first_input = request["inputs"][0]
    if first_input.get("script_sig") in (None, ""):
        return None
    return {"signature": {"class": "synthetic_send"}}


def _raw_predicate(payload: bytes):
    if b"BUG" not in payload:
        return None
    return {"signature": {"class": "synthetic_raw"}}


def main() -> int:
    structured = minimize_structured_request(_send_request(), _structured_predicate)
    request = structured["request"]
    _require(len(request["inputs"]) == 1, "expected one minimized input")
    _require(len(request["recipient_groups"]) == 1, "expected one minimized recipient group")
    _require(request["recipient_groups"][0]["count"] == 1, "expected minimized recipient count")
    _require(request["network"] == "mainnet", "expected canonical network")
    _require(request["silent_payment_version"] == 0, "expected zero silent payment version")
    _require(request["seed"] == 0, "expected zero seed")
    _require(request["flags"] == 0, "expected zero flags")
    _require(request["inputs"][0]["script_sig"] not in (None, ""), "predicate field was removed")
    _require(request["inputs"][0]["txinwitness"] in (None, ""), "expected witness shrink")
    _require(all(item["privkey"] is None for item in request["inputs"]), "expected privkey drop")
    _require(all(item["pubkey"] is None for item in request["inputs"]), "expected pubkey drop")
    _require(
        structured["stats"]["accepted_reductions"] > 0,
        "expected structured minimization to reduce the request",
    )

    raw = minimize_raw_payload(b"prefix-BUG-suffix", _raw_predicate)
    _require(raw["payload"] == b"BUG", "expected raw payload to shrink to BUG")
    _require(raw["stats"]["accepted_reductions"] > 0, "expected raw minimization reductions")

    print("semantic fuzz minimizer smoke OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
