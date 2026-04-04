#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate full official BIP352 cases in SP-DIFFER case format v2."""

import argparse
import json
from pathlib import Path
from typing import Dict, List

from bip352_reference import load_reference_module, verify_reference_manifest
from bip352_semantics import (
    build_case_id,
    build_source,
    compare_receive_semantics_to_official,
    compare_sender_semantics_to_official,
    derive_receive_semantics,
    derive_sender_semantics,
    encode_receive_case_v2,
    encode_send_case_v2,
    parse_case_v2_payload,
)
from semantic_contract import SEMANTIC_CONTRACT_VERSION


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate official BIP352 v2 cases")
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
        "--out-dir",
        type=Path,
        default=Path("tests/vectors/bip352/derived/v2"),
        help="Directory for generated v2 .hex files, expectations, and manifest",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify that generated files are already up to date instead of writing them",
    )
    args = parser.parse_args()

    try:
        manifest, verification, vectors = verify_reference_manifest(
            args.manifest, args.vectors
        )
        reference_module = load_reference_module(
            args.reference_dir / "reference.py", args.reference_dir
        )
    except Exception as exc:
        print("error: {}".format(exc))
        return 2

    expected_files: Dict[Path, bytes] = {}
    manifest_entries: List[Dict[str, object]] = []

    for case_index, case in enumerate(vectors):
        comment = case["comment"]

        for send_index, entry in enumerate(case["sending"]):
            source = build_source(
                manifest["upstream_commit"], case_index, "send", send_index, comment
            )
            payload = encode_send_case_v2(case_index, send_index, entry)
            parsed = parse_case_v2_payload(payload)
            semantic = derive_sender_semantics(reference_module, parsed, source)
            compare_sender_semantics_to_official(semantic, entry)

            base_name = build_case_id(case_index, "send", send_index)
            case_path = args.out_dir / "{}.hex".format(base_name)
            expectation_path = args.out_dir / "{}.expected.json".format(base_name)
            expected_files[case_path] = (payload.hex() + "\n").encode("ascii")
            expected_files[expectation_path] = (
                json.dumps(semantic, indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
            manifest_entries.append(
                {
                    "id": source["id"],
                    "kind": "send",
                    "path": case_path.name,
                    "expectation_path": expectation_path.name,
                    "official_case_index": case_index,
                    "official_send_index": send_index,
                    "official_comment": comment,
                    "semantic_status": semantic["semantic_status"],
                    "output_count_options": semantic["output_count_options"],
                    "notes": semantic["notes"],
                }
            )

        for receive_index, entry in enumerate(case["receiving"]):
            source = build_source(
                manifest["upstream_commit"],
                case_index,
                "receive",
                receive_index,
                comment,
            )
            payload = encode_receive_case_v2(case_index, receive_index, entry)
            parsed = parse_case_v2_payload(payload)
            semantic = derive_receive_semantics(
                reference_module,
                parsed,
                source,
                detailed_outputs_available="outputs" in entry["expected"],
            )
            compare_receive_semantics_to_official(semantic, entry)

            base_name = build_case_id(case_index, "receive", receive_index)
            case_path = args.out_dir / "{}.hex".format(base_name)
            expectation_path = args.out_dir / "{}.expected.json".format(base_name)
            expected_files[case_path] = (payload.hex() + "\n").encode("ascii")
            expected_files[expectation_path] = (
                json.dumps(semantic, indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
            manifest_entries.append(
                {
                    "id": source["id"],
                    "kind": "receive",
                    "path": case_path.name,
                    "expectation_path": expectation_path.name,
                    "official_case_index": case_index,
                    "official_receive_index": receive_index,
                    "official_comment": comment,
                    "semantic_status": semantic["semantic_status"],
                    "detailed_outputs_available": semantic["detailed_outputs_available"],
                    "found_output_count": semantic["found_output_count"],
                    "notes": semantic["notes"],
                }
            )

    derived_manifest = {
        "source_snapshot": str(args.vectors),
        "source_snapshot_sha256": verification["snapshot_sha256"],
        "upstream_commit": manifest["upstream_commit"],
        "case_format_version": 2,
        "semantic_contract_version": SEMANTIC_CONTRACT_VERSION,
        "derived_case_count": len(manifest_entries),
        "derived_send_case_count": sum(1 for item in manifest_entries if item["kind"] == "send"),
        "derived_receive_case_count": sum(
            1 for item in manifest_entries if item["kind"] == "receive"
        ),
        "notes": [
            "These are full official BIP352 send and receive entries encoded into SP-DIFFER case format v2.",
            "Each .expected.json file contains the normalized semantic comparison contract derived from the v2 case and cross-checked against the pinned official upstream expectations.",
        ],
        "cases": manifest_entries,
    }
    manifest_path = args.out_dir / "manifest.json"
    expected_files[manifest_path] = (
        json.dumps(derived_manifest, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")

    if args.check:
        stale = [
            str(path)
            for path, payload in expected_files.items()
            if not path.exists() or path.read_bytes() != payload
        ]
        extras = [
            str(path)
            for path in args.out_dir.glob("*")
            if path.is_file() and path.name != "README.md" and path not in expected_files
        ]
        if stale or extras:
            print("derived v2 case snapshot is out of date")
            for path in stale:
                print("  stale: {}".format(path))
            for path in extras:
                print("  extra: {}".format(path))
            return 2
        print("derived v2 case snapshot OK")
        print("  cases: {}".format(len(manifest_entries)))
        return 0

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for path, payload in expected_files.items():
        path.write_bytes(payload)

    print("generated {} derived v2 cases".format(len(manifest_entries)))
    print("manifest: {}".format(manifest_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
