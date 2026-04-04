#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bridge helpers for compiled runner/compare semantic v2 dispatch."""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from parse_case import CaseV2, parse_case, read_payload
from semantic_adapter import build_semantic_request
from semantic_contract import compare_semantic_results, validate_semantic_result


class SemanticBridgeError(Exception):
    pass


OFFICIAL_CASE_RE = re.compile(r"^official_case_(\d+)_(send|receive)_(\d+)$")


def _read_case_v2(path: Path) -> CaseV2:
    payload = read_payload(str(path), "hex")
    parsed = parse_case(payload)
    if not isinstance(parsed, CaseV2):
        raise SemanticBridgeError("{} is not a v2 case".format(path))
    return parsed


def _expected_path_for_case(case_path: Path) -> Path:
    return case_path.with_suffix(".expected.json")


def _load_expected(path: Path) -> Dict[str, Any]:
    try:
        return validate_semantic_result(json.loads(path.read_text(encoding="utf-8")))
    except FileNotFoundError as exc:
        raise SemanticBridgeError("expectation file not found: {}".format(path)) from exc
    except Exception as exc:
        raise SemanticBridgeError("invalid expectation file {}: {}".format(path, exc)) from exc


def _infer_kind(case: CaseV2) -> str:
    has_send_fields = bool(case.recipient_groups)
    has_receive_fields = bool(
        case.outputs_to_scan
        or case.labels
        or case.receiver_keys.scan_privkey is not None
        or case.receiver_keys.spend_privkey is not None
    )
    if has_send_fields and not has_receive_fields:
        return "send"
    if has_receive_fields and not has_send_fields:
        return "receive"
    raise SemanticBridgeError("unable to infer semantic kind from v2 case")


def _derive_source(case_path: Path, kind: str) -> Dict[str, Any]:
    stem = case_path.stem
    match = OFFICIAL_CASE_RE.match(stem)
    if match:
        case_index = int(match.group(1))
        entry_kind = match.group(2)
        entry_index = int(match.group(3))
        return {
            "kind": entry_kind,
            "comment": stem,
            "case_index": case_index,
            "entry_index": entry_index,
            "id": stem,
        }
    return {
        "kind": kind,
        "comment": case_path.name,
        "case_index": 0,
        "entry_index": 0,
        "id": stem,
    }


def build_request(case_path: Path, expectation_path: Optional[Path], kind: str, network: str,
                  silent_payment_version: int) -> Dict[str, Any]:
    case = _read_case_v2(case_path)
    expected = None
    if expectation_path is None:
        candidate = _expected_path_for_case(case_path)
        if candidate.exists():
            expectation_path = candidate
    if expectation_path is not None:
        expected = _load_expected(expectation_path)

    if expected is not None:
        request_kind = expected["kind"]
        source = expected["source"]
        expectation_hints = None
        if request_kind == "receive":
            expectation_hints = {
                "detailed_outputs_required": bool(
                    expected.get("detailed_outputs_available", True)
                )
            }
        return build_semantic_request(
            request_kind,
            case,
            source,
            network=network,
            silent_payment_version=silent_payment_version,
            expectation_hints=expectation_hints,
        )

    if kind == "auto":
        request_kind = _infer_kind(case)
    else:
        request_kind = kind
    source = _derive_source(case_path, request_kind)
    return build_semantic_request(
        request_kind,
        case,
        source,
        network=network,
        silent_payment_version=silent_payment_version,
    )


def canonicalize_result(payload: Dict[str, Any]) -> Dict[str, Any]:
    return validate_semantic_result(payload)


def compare_to_expected(expected_path: Path, actual_payload: Dict[str, Any]) -> Dict[str, Any]:
    expected = _load_expected(expected_path)
    actual = validate_semantic_result(actual_payload)
    errors = compare_semantic_results(expected, actual)
    return {
        "status": "passed" if not errors else "failed",
        "errors": errors,
        "actual": actual,
    }


def _load_json_input(path: Optional[Path]) -> Dict[str, Any]:
    if path is None:
        raw = sys.stdin.read()
    else:
        raw = path.read_text(encoding="utf-8")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SemanticBridgeError("invalid JSON input: {}".format(exc)) from exc
    if not isinstance(value, dict):
        raise SemanticBridgeError("JSON input must be an object")
    return value


def _write_json_output(payload: Dict[str, Any], json_out: Optional[Path]) -> None:
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if json_out is None:
        sys.stdout.write(text)
    else:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Compiled semantic bridge helper")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_request_parser = subparsers.add_parser(
        "build-request", help="Build a semantic adapter request from a v2 case"
    )
    build_request_parser.add_argument("--case", type=Path, required=True, help="Path to v2 case")
    build_request_parser.add_argument(
        "--expectation",
        type=Path,
        help="Optional expectation JSON path; defaults to sibling .expected.json when present",
    )
    build_request_parser.add_argument(
        "--kind",
        choices=("auto", "send", "receive"),
        default="auto",
        help="Semantic kind override when no expectation file is supplied",
    )
    build_request_parser.add_argument(
        "--network",
        default="mainnet",
        help="Network name for the semantic request",
    )
    build_request_parser.add_argument(
        "--silent-payment-version",
        type=int,
        default=0,
        help="Silent payment version for the semantic request",
    )
    build_request_parser.add_argument(
        "--json-out",
        type=Path,
        help="Optional JSON output path; defaults to stdout",
    )

    validate_result_parser = subparsers.add_parser(
        "validate-result", help="Validate and canonicalize a semantic result"
    )
    validate_result_parser.add_argument("--input", type=Path, help="Optional input JSON path")
    validate_result_parser.add_argument(
        "--json-out",
        type=Path,
        help="Optional canonical JSON output path; defaults to stdout",
    )

    compare_parser = subparsers.add_parser(
        "compare-to-expected",
        help="Compare an actual semantic result against an expectation JSON file",
    )
    compare_parser.add_argument(
        "--expected", type=Path, required=True, help="Expectation JSON path"
    )
    compare_parser.add_argument("--input", type=Path, help="Optional actual JSON path")
    compare_parser.add_argument(
        "--json-out",
        type=Path,
        help="Optional canonical actual JSON output path on success",
    )

    args = parser.parse_args()

    try:
        if args.command == "build-request":
            payload = build_request(
                args.case,
                args.expectation,
                args.kind,
                args.network,
                args.silent_payment_version,
            )
            _write_json_output(payload, args.json_out)
            return 0

        if args.command == "validate-result":
            payload = canonicalize_result(_load_json_input(args.input))
            _write_json_output(payload, args.json_out)
            return 0

        if args.command == "compare-to-expected":
            comparison = compare_to_expected(args.expected, _load_json_input(args.input))
            if comparison["status"] != "passed":
                print("; ".join(comparison["errors"]), file=sys.stderr)
                return 2
            if args.json_out is not None:
                _write_json_output(comparison["actual"], args.json_out)
            return 0
    except Exception as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2

    print("error: unknown command", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
