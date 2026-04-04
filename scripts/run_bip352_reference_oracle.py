#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the vendored upstream BIP352 reference implementation offline."""

import argparse
import subprocess
import sys
from pathlib import Path

from bip352_reference import load_reference_module, verify_reference_manifest
from bip352_vectors import write_json


def summarize_vectors(vectors, k_max: int):
    sending_entries = sum(len(case["sending"]) for case in vectors)
    receiving_entries = sum(len(case["receiving"]) for case in vectors)
    detailed_receive_entries = 0
    count_only_receive_entries = 0
    max_recipient_repeat_count = 0
    max_outputs_to_scan = 0
    over_limit_sending_entries = []

    for case_index, case in enumerate(vectors):
        for send_index, entry in enumerate(case["sending"]):
            recipients = entry["given"]["recipients"]
            group_counts = {}
            for recipient in recipients:
                count = int(recipient.get("count", 1))
                key = "{}|{}".format(recipient["scan_pub_key"], recipient["spend_pub_key"])
                group_counts[key] = group_counts.get(key, 0) + count
                if count > max_recipient_repeat_count:
                    max_recipient_repeat_count = count
            if any(count > k_max for count in group_counts.values()):
                over_limit_sending_entries.append(
                    {
                        "case_index": case_index,
                        "send_index": send_index,
                        "comment": case["comment"],
                        "group_output_counts": sorted(group_counts.values(), reverse=True),
                    }
                )

        for entry in case["receiving"]:
            outputs_to_scan = entry["given"]["outputs"]
            if len(outputs_to_scan) > max_outputs_to_scan:
                max_outputs_to_scan = len(outputs_to_scan)
            if "outputs" in entry["expected"]:
                detailed_receive_entries += 1
            elif "n_outputs" in entry["expected"]:
                count_only_receive_entries += 1
            else:
                raise RuntimeError(
                    "receiving entry missing expected.outputs and expected.n_outputs"
                )

    return {
        "case_count": len(vectors),
        "sending_entry_count": sending_entries,
        "receiving_entry_count": receiving_entries,
        "detailed_receiving_entry_count": detailed_receive_entries,
        "count_only_receiving_entry_count": count_only_receive_entries,
        "max_recipient_repeat_count": max_recipient_repeat_count,
        "max_outputs_to_scan": max_outputs_to_scan,
        "k_max": k_max,
        "over_limit_sending_entries": over_limit_sending_entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the vendored upstream BIP352 reference oracle"
    )
    parser.add_argument(
        "--vectors",
        type=Path,
        default=Path("tests/vectors/bip352/official/send_and_receive_test_vectors.json"),
        help="Path to the vendored official BIP352 vector snapshot",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("tests/vectors/bip352/official/manifest.json"),
        help="Path to the vendored official manifest",
    )
    parser.add_argument(
        "--reference-dir",
        type=Path,
        default=Path("tests/vectors/bip352/official/reference"),
        help="Path to the vendored upstream reference bundle root",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=Path("build/bip352_reference_oracle_report.json"),
        help="Where to write the machine-readable oracle report",
    )
    args = parser.parse_args()

    try:
        manifest, verification, vectors = verify_reference_manifest(
            args.manifest, args.vectors
        )
        reference_script = args.reference_dir / "reference.py"
        reference_module = load_reference_module(reference_script, args.reference_dir)
        summary = summarize_vectors(vectors, int(reference_module.K_max))
        cmd = [sys.executable, str(reference_script), str(args.vectors)]
        result = subprocess.run(cmd, capture_output=True, text=True)
    except Exception as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2

    report = {
        "status": "passed" if result.returncode == 0 else "failed",
        "command": cmd,
        "reference_source": manifest.get("reference_source"),
        "upstream_commit": manifest.get("upstream_commit"),
        "snapshot_path": str(args.vectors),
        "snapshot_sha256": verification["snapshot_sha256"],
        "reference_bundle_verified_file_count": verification[
            "verified_reference_file_count"
        ],
        "summary": summary,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.returncode,
    }
    write_json(args.json_out, report)

    if result.returncode != 0:
        print("FAIL: vendored upstream oracle failed", file=sys.stderr)
        stderr = result.stderr.strip()
        stdout = result.stdout.strip()
        if stderr:
            print(stderr, file=sys.stderr)
        if stdout:
            print(stdout, file=sys.stderr)
        print("  wrote report: {}".format(args.json_out), file=sys.stderr)
        return 2

    print("BIP352 upstream oracle OK")
    print("  sha256: {}".format(report["snapshot_sha256"]))
    print("  cases: {}".format(summary["case_count"]))
    print("  sending entries: {}".format(summary["sending_entry_count"]))
    print("  receiving entries: {}".format(summary["receiving_entry_count"]))
    print(
        "  detailed receiving entries: {}".format(
            summary["detailed_receiving_entry_count"]
        )
    )
    print(
        "  count-only receiving entries: {}".format(
            summary["count_only_receiving_entry_count"]
        )
    )
    print("  K_max: {}".format(summary["k_max"]))
    print(
        "  max recipient repeat count: {}".format(
            summary["max_recipient_repeat_count"]
        )
    )
    print("  max outputs to scan: {}".format(summary["max_outputs_to_scan"]))
    print(
        "  verified reference files: {}".format(
            report["reference_bundle_verified_file_count"]
        )
    )
    print("  wrote report: {}".format(args.json_out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
