#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Automatic shrinking helpers for semantic-worker fuzz failures."""

import json
from copy import deepcopy
from math import ceil
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from semantic_adapter import SemanticAdapterError, validate_semantic_request


class SemanticFuzzMinimizerError(Exception):
    pass


StructuredObservation = Dict[str, Any]
StructuredPredicate = Callable[[Dict[str, Any]], Optional[StructuredObservation]]
RawObservation = Dict[str, Any]
RawPredicate = Callable[[bytes], Optional[RawObservation]]


def canonical_semantic_request_bytes(payload: Dict[str, Any]) -> bytes:
    return (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")


def _path_label(path: Sequence[Any]) -> str:
    parts = []
    for item in path:
        if isinstance(item, int):
            parts.append("[{}]".format(item))
        else:
            parts.append(str(item))
    return ".".join(parts)


def _get_path(payload: Dict[str, Any], path: Sequence[Any]) -> Any:
    value: Any = payload
    for item in path:
        value = value[item]
    return value


def _set_path(payload: Dict[str, Any], path: Sequence[Any], value: Any) -> None:
    target: Any = payload
    for item in path[:-1]:
        target = target[item]
    target[path[-1]] = value


def _count_optional_fields(request: Dict[str, Any]) -> int:
    optional_count = 0
    for item in request["inputs"]:
        for key in ("prevout_script_pubkey", "script_sig", "txinwitness", "privkey", "pubkey"):
            if item.get(key) not in (None, ""):
                optional_count += 1
        optional_count += len(item.get("txinwitness_stack", []))
    return optional_count


def _structured_score(request: Dict[str, Any]) -> Tuple[int, ...]:
    payload_len = len(canonical_semantic_request_bytes(request))
    network_rank = {"mainnet": 0, "testnet": 1, "regtest": 2}[request["network"]]
    recipient_count_sum = sum(group.get("count", 0) for group in request.get("recipient_groups", []))
    return (
        payload_len,
        len(request["inputs"]),
        len(request.get("recipient_groups", [])),
        len(request.get("outputs_to_scan", [])),
        len(request.get("labels", [])),
        recipient_count_sum,
        _count_optional_fields(request),
        0 if "expectation_hints" not in request else 1,
        network_rank,
        0 if int(request.get("silent_payment_version", 0)) == 0 else 1,
        0 if int(request.get("seed", 0)) == 0 else 1,
        0 if int(request.get("flags", 0)) == 0 else 1,
    )


def _record_accept(stats: Dict[str, Any], label: str) -> None:
    stats["accepted_reductions"] += 1
    labels = stats.setdefault("accepted_labels", [])
    if len(labels) < 32:
        labels.append(label)


def _minimize_list_field(
    current: Dict[str, Any],
    path: Sequence[Any],
    min_len: int,
    try_candidate: Callable[[Dict[str, Any], str], bool],
) -> Dict[str, Any]:
    while True:
        values = _get_path(current, path)
        if not isinstance(values, list) or len(values) <= min_len:
            return current

        changed = False
        chunk_count = 2
        while True:
            values = _get_path(current, path)
            if len(values) <= min_len:
                return current
            chunk_size = max(1, ceil(len(values) / chunk_count))
            local_changed = False
            for start in range(0, len(values), chunk_size):
                end = min(len(values), start + chunk_size)
                if len(values) - (end - start) < min_len:
                    continue
                candidate = deepcopy(current)
                _set_path(candidate, path, list(values[:start]) + list(values[end:]))
                if try_candidate(candidate, "drop {} {}:{}".format(_path_label(path), start, end)):
                    current = candidate
                    changed = True
                    local_changed = True
                    break
            if local_changed:
                break
            if chunk_count >= len(values):
                break
            chunk_count = min(len(values), chunk_count * 2)
        if not changed:
            return current


def minimize_structured_request(
    request: Dict[str, Any],
    is_interesting: StructuredPredicate,
) -> Dict[str, Any]:
    try:
        current = validate_semantic_request(request)
    except SemanticAdapterError as exc:
        raise SemanticFuzzMinimizerError(str(exc)) from exc

    observation = is_interesting(current)
    if observation is None:
        raise SemanticFuzzMinimizerError("structured seed does not reproduce the target failure")

    current_score = _structured_score(current)
    stats: Dict[str, Any] = {
        "kind": "structured",
        "candidate_evaluations": 0,
        "accepted_reductions": 0,
        "accepted_labels": [],
        "original_score": list(current_score),
    }

    def try_candidate(candidate: Dict[str, Any], label: str) -> bool:
        nonlocal current, current_score, observation
        stats["candidate_evaluations"] += 1
        try:
            normalized = validate_semantic_request(candidate)
        except SemanticAdapterError:
            return False
        candidate_score = _structured_score(normalized)
        if candidate_score >= current_score:
            return False
        next_observation = is_interesting(normalized)
        if next_observation is None:
            return False
        current = normalized
        current_score = candidate_score
        observation = next_observation
        _record_accept(stats, label)
        return True

    current = _minimize_list_field(current, ("inputs",), 0, try_candidate)
    if current["kind"] == "send":
        current = _minimize_list_field(current, ("recipient_groups",), 0, try_candidate)
    else:
        current = _minimize_list_field(current, ("outputs_to_scan",), 0, try_candidate)
        current = _minimize_list_field(current, ("labels",), 0, try_candidate)

    while True:
        changed = False

        if "expectation_hints" in current:
            candidate = deepcopy(current)
            del candidate["expectation_hints"]
            if try_candidate(candidate, "drop expectation_hints"):
                changed = True
                continue

        for key, value in (
            ("network", "mainnet"),
            ("silent_payment_version", 0),
            ("seed", 0),
            ("flags", 0),
        ):
            if current.get(key) != value:
                candidate = deepcopy(current)
                candidate[key] = value
                if try_candidate(candidate, "set {}={}".format(key, value)):
                    changed = True
                    break
        if changed:
            continue

        for index, item in enumerate(current["inputs"]):
            for key in ("prevout_script_pubkey", "script_sig"):
                if item.get(key) not in (None, ""):
                    candidate = deepcopy(current)
                    candidate["inputs"][index][key] = ""
                    if try_candidate(candidate, "clear inputs[{}].{}".format(index, key)):
                        changed = True
                        break
            if changed:
                break
            if item.get("txinwitness") not in (None, "") or item.get("txinwitness_stack"):
                candidate = deepcopy(current)
                candidate["inputs"][index]["txinwitness"] = ""
                candidate["inputs"][index]["txinwitness_stack"] = []
                if try_candidate(candidate, "clear inputs[{}].txinwitness".format(index)):
                    changed = True
                    break
        if changed:
            continue

        for key in ("privkey", "pubkey"):
            if any(item.get(key) is not None for item in current["inputs"]):
                candidate = deepcopy(current)
                for item in candidate["inputs"]:
                    item[key] = None
                if try_candidate(candidate, "drop all {}".format(key)):
                    changed = True
                    break
        if changed:
            continue

        if current["kind"] == "send":
            for index, group in enumerate(current["recipient_groups"]):
                if int(group["count"]) > 1:
                    candidate = deepcopy(current)
                    candidate["recipient_groups"][index]["count"] = 1
                    if try_candidate(candidate, "set recipient_groups[{}].count=1".format(index)):
                        changed = True
                        break
        if not changed:
            break

    stats["final_score"] = list(current_score)
    return {
        "request": current,
        "observation": observation,
        "stats": stats,
    }


def minimize_raw_payload(payload: bytes, is_interesting: RawPredicate) -> Dict[str, Any]:
    current = bytes(payload)
    observation = is_interesting(current)
    if observation is None:
        raise SemanticFuzzMinimizerError("raw seed does not reproduce the target failure")

    stats: Dict[str, Any] = {
        "kind": "raw",
        "candidate_evaluations": 0,
        "accepted_reductions": 0,
        "accepted_labels": [],
        "original_size": len(current),
    }

    while True:
        if len(current) <= 1:
            break
        changed = False
        chunk_count = 2
        while True:
            chunk_size = max(1, ceil(len(current) / chunk_count))
            local_changed = False
            for start in range(0, len(current), chunk_size):
                end = min(len(current), start + chunk_size)
                candidate = current[:start] + current[end:]
                if len(candidate) >= len(current):
                    continue
                stats["candidate_evaluations"] += 1
                next_observation = is_interesting(candidate)
                if next_observation is None:
                    continue
                current = candidate
                observation = next_observation
                _record_accept(stats, "drop bytes {}:{}".format(start, end))
                changed = True
                local_changed = True
                break
            if local_changed:
                break
            if chunk_count >= len(current):
                break
            chunk_count = min(len(current), chunk_count * 2)
        if not changed:
            break

    stats["final_size"] = len(current)
    return {
        "payload": current,
        "observation": observation,
        "stats": stats,
    }
