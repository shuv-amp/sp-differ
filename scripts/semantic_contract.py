#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validation and comparison helpers for semantic comparison artifacts."""

from copy import deepcopy
from typing import Any, Dict, List


SEMANTIC_CONTRACT_VERSION = 1
KNOWN_KINDS = {"send", "receive"}
KNOWN_STATUSES = {
    "ok",
    "no_eligible_inputs",
    "zero_scalar",
    "point_at_infinity",
    "recipient_limit_exceeded",
    "invalid_input",
    "invalid_pubkey",
    "tweak_out_of_range",
    "internal",
}


class SemanticContractError(Exception):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SemanticContractError(message)


def _is_hex_string(value: Any, expected_len: int) -> bool:
    if not isinstance(value, str) or len(value) != expected_len:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _normalize_output_sets(output_sets: List[List[str]]) -> List[List[str]]:
    normalized = []
    seen = set()
    for output_set in output_sets:
        canonical = tuple(sorted(set(output_set)))
        if canonical not in seen:
            seen.add(canonical)
            normalized.append(list(canonical))
    normalized.sort(key=lambda item: tuple(item))
    return normalized


def _normalize_shared_secrets(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized = []
    for item in items:
        normalized.append(
            {
                "scan_pubkey": item["scan_pubkey"],
                "shared_secret": item.get("shared_secret"),
            }
        )
    normalized.sort(key=lambda item: item["scan_pubkey"])
    return normalized


def _normalize_found_outputs(items: List[Dict[str, str]]) -> List[Dict[str, str]]:
    normalized = []
    seen = set()
    for item in items:
        key = (item["pub_key"], item["priv_key_tweak"])
        if key in seen:
            continue
        seen.add(key)
        normalized.append({"pub_key": key[0], "priv_key_tweak": key[1]})
    normalized.sort(key=lambda item: (item["pub_key"], item["priv_key_tweak"]))
    return normalized


def normalize_semantic_result(payload: Dict[str, Any]) -> Dict[str, Any]:
    normalized = deepcopy(payload)
    normalized["input_pubkeys"] = list(normalized.get("input_pubkeys", []))
    normalized["notes"] = sorted(set(normalized.get("notes", [])))

    if normalized["kind"] == "send":
        normalized["sender_shared_secrets"] = _normalize_shared_secrets(
            normalized.get("sender_shared_secrets", [])
        )
        normalized["acceptable_output_sets"] = _normalize_output_sets(
            normalized.get("acceptable_output_sets", [])
        )
        normalized["output_count_options"] = sorted(
            {len(output_set) for output_set in normalized["acceptable_output_sets"]}
        )
    else:
        normalized["found_outputs"] = _normalize_found_outputs(
            normalized.get("found_outputs", [])
        )
        normalized["found_output_count"] = int(normalized.get("found_output_count", 0))

    return normalized


def validate_semantic_result(payload: Dict[str, Any]) -> Dict[str, Any]:
    _require(isinstance(payload, dict), "semantic result must be an object")
    _require(
        payload.get("semantic_contract_version") == SEMANTIC_CONTRACT_VERSION,
        "unsupported semantic contract version",
    )
    _require(payload.get("case_format_version") == 2, "case_format_version must be 2")
    _require(payload.get("kind") in KNOWN_KINDS, "unknown kind")
    _require(payload.get("semantic_status") in KNOWN_STATUSES, "unknown semantic_status")
    _require(isinstance(payload.get("source"), dict), "missing source")
    _require(isinstance(payload.get("input_pubkeys"), list), "input_pubkeys must be a list")
    _require(isinstance(payload.get("notes"), list), "notes must be a list")

    for pubkey in payload["input_pubkeys"]:
        _require(_is_hex_string(pubkey, 66), "invalid input_pubkey")

    input_hash = payload.get("input_hash")
    _require(input_hash is None or _is_hex_string(input_hash, 64), "invalid input_hash")

    source = payload["source"]
    _require(source.get("kind") in KNOWN_KINDS, "invalid source.kind")
    _require(isinstance(source.get("comment"), str), "invalid source.comment")
    _require(isinstance(source.get("case_index"), int), "invalid source.case_index")
    _require(isinstance(source.get("entry_index"), int), "invalid source.entry_index")
    _require(isinstance(source.get("id"), str) and source["id"], "invalid source.id")

    if payload["kind"] == "send":
        input_private_key_sum = payload.get("input_private_key_sum")
        _require(
            input_private_key_sum is None or _is_hex_string(input_private_key_sum, 64),
            "invalid input_private_key_sum",
        )
        sender_shared_secrets = payload.get("sender_shared_secrets")
        acceptable_output_sets = payload.get("acceptable_output_sets")
        output_count_options = payload.get("output_count_options")
        _require(
            isinstance(sender_shared_secrets, list), "sender_shared_secrets must be a list"
        )
        _require(
            isinstance(acceptable_output_sets, list), "acceptable_output_sets must be a list"
        )
        _require(
            isinstance(output_count_options, list), "output_count_options must be a list"
        )
        for item in sender_shared_secrets:
            _require(isinstance(item, dict), "invalid sender_shared_secrets item")
            _require(_is_hex_string(item.get("scan_pubkey"), 66), "invalid scan_pubkey")
            shared_secret = item.get("shared_secret")
            _require(
                shared_secret is None or _is_hex_string(shared_secret, 66),
                "invalid shared_secret",
            )
        for output_set in acceptable_output_sets:
            _require(isinstance(output_set, list), "invalid acceptable_output_set")
            for output in output_set:
                _require(_is_hex_string(output, 64), "invalid output xonly pubkey")
        for count in output_count_options:
            _require(isinstance(count, int) and count >= 0, "invalid output_count_option")
    else:
        receiving_addresses = payload.get("receiving_addresses")
        input_pubkey_sum = payload.get("input_pubkey_sum")
        tweak = payload.get("tweak")
        shared_secret = payload.get("shared_secret")
        detailed_outputs_available = payload.get("detailed_outputs_available")
        found_output_count = payload.get("found_output_count")
        found_outputs = payload.get("found_outputs")
        _require(
            isinstance(receiving_addresses, list), "receiving_addresses must be a list"
        )
        for address in receiving_addresses:
            _require(isinstance(address, str) and address, "invalid receiving address")
        _require(
            input_pubkey_sum is None or _is_hex_string(input_pubkey_sum, 66),
            "invalid input_pubkey_sum",
        )
        _require(tweak is None or _is_hex_string(tweak, 66), "invalid tweak")
        _require(
            shared_secret is None or _is_hex_string(shared_secret, 66),
            "invalid shared_secret",
        )
        _require(
            isinstance(detailed_outputs_available, bool),
            "detailed_outputs_available must be boolean",
        )
        _require(
            isinstance(found_output_count, int) and found_output_count >= 0,
            "invalid found_output_count",
        )
        _require(isinstance(found_outputs, list), "found_outputs must be a list")
        for item in found_outputs:
            _require(isinstance(item, dict), "invalid found_outputs item")
            _require(_is_hex_string(item.get("pub_key"), 64), "invalid found_outputs.pub_key")
            _require(
                _is_hex_string(item.get("priv_key_tweak"), 64),
                "invalid found_outputs.priv_key_tweak",
            )
        if detailed_outputs_available:
            _require(
                len(found_outputs) == found_output_count,
                "detailed found_outputs length mismatch",
            )

    return normalize_semantic_result(payload)


def compare_semantic_results(expected: Dict[str, Any], actual: Dict[str, Any]) -> List[str]:
    expected_norm = validate_semantic_result(expected)
    actual_norm = validate_semantic_result(actual)
    errors: List[str] = []

    for key in (
        "semantic_contract_version",
        "case_format_version",
        "kind",
        "semantic_status",
        "source",
        "input_pubkeys",
        "input_hash",
    ):
        if expected_norm[key] != actual_norm[key]:
            errors.append("field mismatch: {}".format(key))

    if expected_norm["kind"] == "send":
        for key in ("input_private_key_sum", "sender_shared_secrets"):
            if expected_norm.get(key) != actual_norm.get(key):
                errors.append("field mismatch: {}".format(key))

        expected_sets = {
            tuple(output_set) for output_set in expected_norm["acceptable_output_sets"]
        }
        actual_sets = {
            tuple(output_set) for output_set in actual_norm["acceptable_output_sets"]
        }
        if not actual_sets:
            errors.append("actual acceptable_output_sets is empty")
        elif not actual_sets.issubset(expected_sets):
            errors.append("actual acceptable_output_sets not accepted by expected contract")

        if not set(actual_norm["output_count_options"]).issubset(
            set(expected_norm["output_count_options"])
        ):
            errors.append("actual output_count_options not accepted by expected contract")
    else:
        for key in ("receiving_addresses", "input_pubkey_sum", "tweak", "shared_secret"):
            if expected_norm.get(key) != actual_norm.get(key):
                errors.append("field mismatch: {}".format(key))

        if expected_norm["found_output_count"] != actual_norm["found_output_count"]:
            errors.append("field mismatch: found_output_count")

        if expected_norm["detailed_outputs_available"]:
            if actual_norm["found_outputs"] != expected_norm["found_outputs"]:
                errors.append("field mismatch: found_outputs")

    return errors
