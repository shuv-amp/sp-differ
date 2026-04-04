#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Helpers for semantic adapter request construction and validation."""

from copy import deepcopy
from typing import Any, Dict, List

from parse_case import (
    CaseHeaderV2,
    CaseV2,
    InputEntryV2,
    RecipientGroupV2,
    ReceiverKeyMaterialV2,
)


SEMANTIC_ADAPTER_REQUEST_VERSION = 1
KNOWN_KINDS = {"send", "receive"}
KNOWN_NETWORKS = {"mainnet", "testnet", "regtest"}
INPUT_TYPE_NAMES = {
    0x01: "p2wpkh",
    0x02: "p2tr",
    0x03: "p2sh-p2wpkh",
    0x04: "p2pkh",
}
INPUT_TYPE_CODES = {value: key for key, value in INPUT_TYPE_NAMES.items()}

FLAG_INPUT_PRIVATE_KEYS = 1 << 1
FLAG_INPUT_PUBLIC_KEYS = 1 << 2
FLAG_PREVOUT_SCRIPT_PUBKEYS = 1 << 3
FLAG_SCRIPT_SIGS = 1 << 4
FLAG_TXINWITNESSES = 1 << 5
FLAG_RECIPIENT_GROUPS = 1 << 6
FLAG_OUTPUTS_TO_SCAN = 1 << 7
FLAG_RECEIVER_KEY_MATERIAL = 1 << 8


class SemanticAdapterError(Exception):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SemanticAdapterError(message)


def _is_hex_string(value: Any, expected_len: int = None) -> bool:
    if not isinstance(value, str):
        return False
    if expected_len is not None and len(value) != expected_len:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _read_compact_size(buf: bytes, off: int) -> (int, int):
    if off >= len(buf):
        raise SemanticAdapterError("unexpected end of txinwitness")
    value = buf[off]
    off += 1
    if value < 253:
        return value, off
    if value == 253:
        if off + 2 > len(buf):
            raise SemanticAdapterError("unexpected end of txinwitness")
        return int.from_bytes(buf[off : off + 2], "little"), off + 2
    if value == 254:
        if off + 4 > len(buf):
            raise SemanticAdapterError("unexpected end of txinwitness")
        return int.from_bytes(buf[off : off + 4], "little"), off + 4
    if off + 8 > len(buf):
        raise SemanticAdapterError("unexpected end of txinwitness")
    return int.from_bytes(buf[off : off + 8], "little"), off + 8


def decode_txinwitness_stack(serialized: bytes) -> List[bytes]:
    if not serialized:
        return []
    off = 0
    item_count, off = _read_compact_size(serialized, off)
    stack: List[bytes] = []
    for _ in range(item_count):
        size, off = _read_compact_size(serialized, off)
        if off + size > len(serialized):
            raise SemanticAdapterError("unexpected end of txinwitness item")
        stack.append(serialized[off : off + size])
        off += size
    if off != len(serialized):
        raise SemanticAdapterError("trailing bytes in txinwitness")
    return stack


def build_semantic_request(
    kind: str,
    case: CaseV2,
    source: Dict[str, Any],
    network: str = "mainnet",
    silent_payment_version: int = 0,
    expectation_hints: Dict[str, Any] = None,
) -> Dict[str, Any]:
    _require(kind in KNOWN_KINDS, "unknown kind")
    inputs = []
    for entry in case.inputs:
        txinwitness = bytes(entry.txinwitness or b"")
        inputs.append(
            {
                "outpoint_txid": bytes(entry.outpoint_txid)[::-1].hex(),
                "outpoint_vout": int(entry.outpoint_vout),
                "input_type": INPUT_TYPE_NAMES[int(entry.input_type)],
                "prevout_script_pubkey": None
                if entry.prevout_script_pubkey is None
                else bytes(entry.prevout_script_pubkey).hex(),
                "script_sig": None if entry.script_sig is None else bytes(entry.script_sig).hex(),
                "txinwitness": None if entry.txinwitness is None else txinwitness.hex(),
                "txinwitness_stack": [item.hex() for item in decode_txinwitness_stack(txinwitness)],
                "privkey": None if entry.privkey is None else bytes(entry.privkey).hex(),
                "pubkey": None if entry.pubkey is None else bytes(entry.pubkey).hex(),
            }
        )

    payload: Dict[str, Any] = {
        "semantic_adapter_request_version": SEMANTIC_ADAPTER_REQUEST_VERSION,
        "case_format_version": 2,
        "kind": kind,
        "network": network,
        "silent_payment_version": int(silent_payment_version),
        "seed": int(case.header.seed),
        "flags": int(case.header.flags),
        "source": deepcopy(source),
        "inputs": inputs,
    }
    if expectation_hints is not None:
        payload["expectation_hints"] = deepcopy(expectation_hints)

    if kind == "send":
        payload["recipient_groups"] = [
            {
                "scan_pubkey": bytes(group.scan_pubkey).hex(),
                "spend_pubkey": bytes(group.spend_pubkey).hex(),
                "count": int(group.count),
            }
            for group in case.recipient_groups
        ]
    else:
        payload["outputs_to_scan"] = [bytes(output).hex() for output in case.outputs_to_scan]
        payload["receiver_keys"] = {
            "scan_privkey": None
            if case.receiver_keys.scan_privkey is None
            else bytes(case.receiver_keys.scan_privkey).hex(),
            "spend_privkey": None
            if case.receiver_keys.spend_privkey is None
            else bytes(case.receiver_keys.spend_privkey).hex(),
        }
        payload["labels"] = [int(label) for label in case.labels]

    return validate_semantic_request(payload)


def validate_semantic_request(payload: Dict[str, Any]) -> Dict[str, Any]:
    _require(isinstance(payload, dict), "request must be an object")
    _require(
        payload.get("semantic_adapter_request_version") == SEMANTIC_ADAPTER_REQUEST_VERSION,
        "unsupported semantic adapter request version",
    )
    _require(payload.get("case_format_version") == 2, "case_format_version must be 2")
    _require(payload.get("kind") in KNOWN_KINDS, "unknown kind")
    _require(payload.get("network") in KNOWN_NETWORKS, "unknown network")
    _require(
        isinstance(payload.get("silent_payment_version"), int)
        and payload["silent_payment_version"] >= 0,
        "invalid silent_payment_version",
    )
    _require(isinstance(payload.get("seed"), int), "invalid seed")
    _require(isinstance(payload.get("flags"), int), "invalid flags")
    _require(isinstance(payload.get("source"), dict), "missing source")
    _require(isinstance(payload.get("inputs"), list), "inputs must be a list")
    expectation_hints = payload.get("expectation_hints")
    _require(
        expectation_hints is None or isinstance(expectation_hints, dict),
        "expectation_hints must be an object",
    )

    source = payload["source"]
    _require(source.get("kind") in KNOWN_KINDS, "invalid source.kind")
    _require(source.get("kind") == payload.get("kind"), "source.kind mismatch")
    _require(isinstance(source.get("comment"), str), "invalid source.comment")
    _require(isinstance(source.get("case_index"), int), "invalid source.case_index")
    _require(isinstance(source.get("entry_index"), int), "invalid source.entry_index")
    _require(isinstance(source.get("id"), str) and source["id"], "invalid source.id")

    normalized = deepcopy(payload)
    for item in normalized["inputs"]:
        _require(isinstance(item, dict), "invalid input entry")
        _require(_is_hex_string(item.get("outpoint_txid"), 64), "invalid outpoint_txid")
        _require(
            isinstance(item.get("outpoint_vout"), int) and item["outpoint_vout"] >= 0,
            "invalid outpoint_vout",
        )
        _require(item.get("input_type") in INPUT_TYPE_CODES, "invalid input_type")
        for key in ("script_sig", "txinwitness", "privkey"):
            value = item.get(key)
            _require(value is None or _is_hex_string(value), "invalid {}".format(key))
        prevout_script_pubkey = item.get("prevout_script_pubkey")
        _require(
            prevout_script_pubkey is None
            or (_is_hex_string(prevout_script_pubkey) and len(prevout_script_pubkey) > 0),
            "invalid prevout_script_pubkey",
        )
        _require(
            item.get("pubkey") is None or _is_hex_string(item["pubkey"], 66),
            "invalid pubkey",
        )
        stack = item.get("txinwitness_stack")
        _require(isinstance(stack, list), "txinwitness_stack must be a list")
        for stack_item in stack:
            _require(_is_hex_string(stack_item), "invalid txinwitness stack item")

    if normalized["kind"] == "send":
        groups = normalized.get("recipient_groups")
        _require(isinstance(groups, list), "recipient_groups must be a list")
        _require(bool(groups), "recipient_groups must not be empty")
        for group in groups:
            _require(isinstance(group, dict), "invalid recipient_group")
            _require(_is_hex_string(group.get("scan_pubkey"), 66), "invalid scan_pubkey")
            _require(_is_hex_string(group.get("spend_pubkey"), 66), "invalid spend_pubkey")
            _require(
                isinstance(group.get("count"), int) and group["count"] > 0,
                "invalid recipient count",
            )
    else:
        outputs = normalized.get("outputs_to_scan")
        receiver_keys = normalized.get("receiver_keys")
        labels = normalized.get("labels")
        _require(isinstance(outputs, list), "outputs_to_scan must be a list")
        for output in outputs:
            _require(_is_hex_string(output, 64), "invalid outputs_to_scan entry")
        _require(isinstance(receiver_keys, dict), "receiver_keys must be an object")
        _require(
            _is_hex_string(receiver_keys.get("scan_privkey"), 64),
            "invalid receiver scan_privkey",
        )
        _require(
            _is_hex_string(receiver_keys.get("spend_privkey"), 64),
            "invalid receiver spend_privkey",
        )
        _require(isinstance(labels, list), "labels must be a list")
        for label in labels:
            _require(isinstance(label, int) and label >= 0, "invalid label")
        if expectation_hints is not None and "detailed_outputs_required" in expectation_hints:
            _require(
                isinstance(expectation_hints["detailed_outputs_required"], bool),
                "invalid detailed_outputs_required hint",
            )

    return normalized


def derive_case_flags_from_semantic_request(payload: Dict[str, Any]) -> int:
    request = validate_semantic_request(payload)
    flags = 0
    if any(item.get("privkey") is not None for item in request["inputs"]):
        flags |= FLAG_INPUT_PRIVATE_KEYS
    if any(item.get("pubkey") is not None for item in request["inputs"]):
        flags |= FLAG_INPUT_PUBLIC_KEYS
    if any(item.get("prevout_script_pubkey") not in (None, "") for item in request["inputs"]):
        flags |= FLAG_PREVOUT_SCRIPT_PUBKEYS
    if any(item.get("script_sig") not in (None, "") for item in request["inputs"]):
        flags |= FLAG_SCRIPT_SIGS
    if any(item.get("txinwitness") not in (None, "") for item in request["inputs"]):
        flags |= FLAG_TXINWITNESSES
    if request["kind"] == "send":
        if request["recipient_groups"]:
            flags |= FLAG_RECIPIENT_GROUPS
    else:
        if request["outputs_to_scan"]:
            flags |= FLAG_OUTPUTS_TO_SCAN
        flags |= FLAG_RECEIVER_KEY_MATERIAL
    return flags


def case_from_semantic_request(
    payload: Dict[str, Any], preserve_declared_flags: bool = True
) -> CaseV2:
    request = validate_semantic_request(payload)
    flags = derive_case_flags_from_semantic_request(request)

    inputs = []
    for item in request["inputs"]:
        inputs.append(
            InputEntryV2(
                outpoint_txid=bytes.fromhex(item["outpoint_txid"])[::-1],
                outpoint_vout=int(item["outpoint_vout"]),
                input_type=INPUT_TYPE_CODES[item["input_type"]],
                prevout_script_pubkey=None
                if item["prevout_script_pubkey"] is None
                else bytes.fromhex(item["prevout_script_pubkey"]),
                script_sig=None if item["script_sig"] is None else bytes.fromhex(item["script_sig"]),
                txinwitness=None
                if item["txinwitness"] is None
                else bytes.fromhex(item["txinwitness"]),
                privkey=None if item["privkey"] is None else bytes.fromhex(item["privkey"]),
                pubkey=None if item["pubkey"] is None else bytes.fromhex(item["pubkey"]),
            )
        )

    if request["kind"] == "send":
        flags |= FLAG_RECIPIENT_GROUPS
        recipient_groups = [
            RecipientGroupV2(
                scan_pubkey=bytes.fromhex(group["scan_pubkey"]),
                spend_pubkey=bytes.fromhex(group["spend_pubkey"]),
                count=int(group["count"]),
            )
            for group in request["recipient_groups"]
        ]
        outputs_to_scan = []
        receiver_keys = ReceiverKeyMaterialV2(scan_privkey=None, spend_privkey=None)
        labels: List[int] = []
    else:
        flags |= FLAG_OUTPUTS_TO_SCAN | FLAG_RECEIVER_KEY_MATERIAL
        recipient_groups = []
        outputs_to_scan = [bytes.fromhex(output) for output in request["outputs_to_scan"]]
        receiver_keys = ReceiverKeyMaterialV2(
            scan_privkey=bytes.fromhex(request["receiver_keys"]["scan_privkey"]),
            spend_privkey=bytes.fromhex(request["receiver_keys"]["spend_privkey"]),
        )
        labels = [int(label) for label in request["labels"]]

    return CaseV2(
        header=CaseHeaderV2(
            version=2,
            seed=int(request.get("seed", 0)),
            flags=int(request["flags"]) if preserve_declared_flags else flags,
            input_count=len(inputs),
            recipient_group_count=len(recipient_groups),
            scan_output_count=len(outputs_to_scan),
            label_count=len(labels),
        ),
        inputs=inputs,
        recipient_groups=recipient_groups,
        outputs_to_scan=outputs_to_scan,
        receiver_keys=receiver_keys,
        labels=labels,
    )
