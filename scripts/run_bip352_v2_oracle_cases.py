#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the vendored oracle against generated v2 cases and compare semantics."""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from bip352_reference import load_reference_module, verify_reference_manifest
from bip352_semantics import derive_receive_semantics, derive_sender_semantics, parse_case_v2_payload
from semantic_contract import compare_semantic_results, validate_semantic_result
from bip352_vectors import write_json


def main() -> int:
    parser = argparse.ArgumentParser(description="Run semantic oracle checks on derived v2 cases")
    parser.add_argument(
        "--official-manifest",
        type=Path,
        default=Path("tests/vectors/bip352/official/manifest.json"),
        help="Path to the vendored official manifest",
    )
    parser.add_argument(
        "--official-vectors",
        type=Path,
        default=Path("tests/vectors/bip352/official/send_and_receive_test_vectors.json"),
        help="Path to the vendored official vector snapshot",
    )
    parser.add_argument(
        "--reference-dir",
        type=Path,
        default=Path("tests/vectors/bip352/official/reference"),
        help="Path to the vendored upstream reference bundle root",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("tests/vectors/bip352/derived/v2/manifest.json"),
        help="Path to the derived v2 manifest",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=Path("build/bip352_v2_oracle_compare_report.json"),
        help="Where to write the machine-readable compare report",
    )
    args = parser.parse_args()

    try:
        official_manifest, verification, _ = verify_reference_manifest(
            args.official_manifest, args.official_vectors
        )
        reference_module = load_reference_module(
            args.reference_dir / "reference.py", args.reference_dir
        )
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        cases = manifest.get("cases", [])
        if not isinstance(cases, list) or not cases:
            raise RuntimeError("derived manifest has no cases")
    except Exception as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2

    failures: List[Dict[str, Any]] = []
    for item in cases:
        case_path = args.manifest.parent / item["path"]
        expectation_path = args.manifest.parent / item["expectation_path"]
        expected = validate_semantic_result(
            json.loads(expectation_path.read_text(encoding="utf-8"))
        )
        case = parse_case_v2_payload(bytes.fromhex(case_path.read_text(encoding="ascii").strip()))
        if item["kind"] == "send":
            actual = derive_sender_semantics(reference_module, case, expected["source"])
        else:
            actual = derive_receive_semantics(
                reference_module,
                case,
                expected["source"],
                detailed_outputs_available=expected["detailed_outputs_available"],
            )
        errors = compare_semantic_results(expected, actual)
        if errors:
            failures.append(
                {
                    "id": item["id"],
                    "kind": item["kind"],
                    "case_path": str(case_path),
                    "expectation_path": str(expectation_path),
                    "errors": errors,
                }
            )

    report = {
        "status": "passed" if not failures else "failed",
        "upstream_commit": official_manifest.get("upstream_commit"),
        "snapshot_sha256": verification["snapshot_sha256"],
        "derived_manifest": str(args.manifest),
        "derived_case_count": len(cases),
        "failed_case_count": len(failures),
        "failures": failures,
    }
    write_json(args.json_out, report)

    if failures:
        print("FAIL: v2 oracle compare failed", file=sys.stderr)
        for failure in failures[:10]:
            print(
                "  {}: {}".format(
                    failure["id"], ", ".join(failure["errors"])
                ),
                file=sys.stderr,
            )
        print("  wrote report: {}".format(args.json_out), file=sys.stderr)
        return 2

    print("BIP352 v2 oracle compare OK")
    print("  sha256: {}".format(report["snapshot_sha256"]))
    print("  cases: {}".format(report["derived_case_count"]))
    print("  wrote report: {}".format(args.json_out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
