#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate the subset of official BIP352 vectors that fit SP-DIFFER case format v1."""

import argparse
import json
from pathlib import Path
from typing import Dict, List

from bip352_vectors import (
    VectorError,
    encode_case_v1_hex,
    project_send_entry_to_v1,
    sha256_hex,
    validate_vectors,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate projectable official BIP352 send cases")
    parser.add_argument(
        "--vectors",
        type=Path,
        default=Path("tests/vectors/bip352/official/send_and_receive_test_vectors.json"),
        help="Path to the vendored official vector snapshot",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("tests/vectors/bip352/derived/v1"),
        help="Directory for generated .hex files and manifest",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify that generated files are already up to date instead of writing them",
    )
    args = parser.parse_args()

    try:
        raw = args.vectors.read_bytes()
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
    projections = [projection for projection in projections if projection["projectable"]]

    manifest_entries: List[Dict[str, object]] = []
    expected_files: Dict[Path, bytes] = {}
    for projection in projections:
        filename = "official_case_{:02d}_send_{:02d}.hex".format(
            projection["case_index"], projection["send_index"]
        )
        rel_path = Path(filename)
        payload = (encode_case_v1_hex(projection) + "\n").encode("ascii")
        expected_files[args.out_dir / rel_path] = payload

        manifest_entries.append(
            {
                "path": str(rel_path),
                "official_case_index": projection["case_index"],
                "official_send_index": projection["send_index"],
                "official_comment": projection["comment"],
                "input_types": projection["input_types"],
                "negative": projection["negative"],
                "output_count": projection["output_count"],
                "scan_pub_key": projection["scan_pub_key"],
                "spend_pub_key": projection["spend_pub_key"],
                "expected_outputs_xonly_groups": projection["expected"]["outputs"],
                "expected_shared_secrets": projection["expected"]["shared_secrets"],
                "expected_input_private_key_sum": projection["expected"].get("input_private_key_sum"),
                "expected_input_pub_keys": projection["expected"]["input_pub_keys"],
            }
        )

    manifest = {
        "source_snapshot": str(args.vectors),
        "source_snapshot_sha256": sha256_hex(raw),
        "case_format": "v1",
        "derived_case_count": len(manifest_entries),
        "notes": [
            "These are sender-side official BIP352 vectors that fit the current SP-DIFFER case format v1 without changing the format.",
            "Receiving vectors are not represented here because v1 does not model outputs-to-scan, receiver key material, or input pubkey extraction context.",
        ],
        "cases": manifest_entries,
    }
    manifest_path = args.out_dir / "manifest.json"
    expected_files[manifest_path] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")

    if args.check:
        stale = [str(path) for path, payload in expected_files.items() if not path.exists() or path.read_bytes() != payload]
        extra = [
            str(path)
            for path in args.out_dir.glob("*.hex")
            if path not in expected_files
        ]
        if stale or extra:
            print("derived case snapshot is out of date")
            for path in stale:
                print("  stale: {}".format(path))
            for path in extra:
                print("  extra: {}".format(path))
            return 2
        print("derived case snapshot OK")
        print("  cases: {}".format(len(manifest_entries)))
        return 0

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for path, payload in expected_files.items():
        path.write_bytes(payload)

    print("generated {} derived v1 cases".format(len(manifest_entries)))
    print("manifest: {}".format(manifest_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
