#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate and summarize the vendored official BIP352 vectors."""

import argparse
import json
from pathlib import Path

from bip352_vectors import (
    VectorError,
    project_send_entry_to_v1,
    sha256_hex,
    summarize_vectors,
    validate_vectors,
    write_json,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit the vendored BIP352 vector snapshot")
    parser.add_argument(
        "path",
        type=Path,
        help="Path to the vendored send_and_receive_test_vectors.json file",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Optional path for a machine-readable audit report",
    )
    args = parser.parse_args()

    try:
        raw = args.path.read_bytes()
        vectors = validate_vectors(json.loads(raw.decode("utf-8")))
    except VectorError as exc:
        print("error: {}".format(exc))
        return 2
    except Exception as exc:
        print("error: {}".format(exc))
        return 2

    projections = [
        project_send_entry_to_v1(case_index, send_index, case, entry)
        for case_index, case in enumerate(vectors)
        for send_index, entry in enumerate(case["sending"])
    ]
    compatible = [projection for projection in projections if projection["projectable"]]
    blocked = [projection for projection in projections if not projection["projectable"]]
    summary = summarize_vectors(vectors)
    report = {
        "snapshot_path": str(args.path),
        "snapshot_sha256": sha256_hex(raw),
        "summary": summary,
        "projectable_sending_cases": [
            {
                "case_index": item["case_index"],
                "send_index": item["send_index"],
                "comment": item["comment"],
                "input_types": item["input_types"],
                "output_count": item["output_count"],
                "negative": item["negative"],
            }
            for item in compatible
        ],
        "blocked_sending_cases": [
            {
                "case_index": item["case_index"],
                "send_index": item["send_index"],
                "comment": item["comment"],
                "reasons": item["reasons"],
                "input_types": item["input_types"],
                "unique_recipient_group_count": item["unique_recipient_group_count"],
            }
            for item in blocked
        ],
        "receiving_v1_projection": {
            "projectable_entries": 0,
            "blocked_entries": sum(len(case["receiving"]) for case in vectors),
            "blocking_reasons": [
                "missing_outputs_to_scan",
                "missing_receiver_key_material",
                "missing_input_extraction_context",
            ],
        },
    }

    print("BIP352 vector snapshot OK")
    print("  sha256: {}".format(report["snapshot_sha256"]))
    print("  cases: {}".format(summary["case_count"]))
    print("  sending entries: {}".format(summary["sending_entry_count"]))
    print("  receiving entries: {}".format(summary["receiving_entry_count"]))
    print("  v1-projectable sending entries: {}".format(summary["projectable_sending_entries"]))
    print("  blocked sending entries: {}".format(summary["blocked_sending_entries"]))
    print("  receiving entries blocked by v1 format: {}".format(report["receiving_v1_projection"]["blocked_entries"]))

    if args.json_out is not None:
        write_json(args.json_out, report)
        print("  wrote report: {}".format(args.json_out))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
