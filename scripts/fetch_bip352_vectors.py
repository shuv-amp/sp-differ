#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fetch and pin the official BIP352 vector snapshot."""

import argparse
import json
from pathlib import Path

from bip352_vectors import (
    REFERENCE_BUNDLE_FILES,
    REFERENCE_RELATIVE_PATH,
    VECTOR_RELATIVE_PATH,
    VectorError,
    fetch_bytes,
    raw_url,
    resolve_branch_head,
    sha256_hex,
    utc_now_iso,
    validate_vectors,
    write_json,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch the official BIP352 vector snapshot")
    parser.add_argument(
        "--commit",
        default="",
        help="Upstream bitcoin/bips commit to pin. Defaults to the current master head.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("tests/vectors/bip352/official/send_and_receive_test_vectors.json"),
        help="Where to write the vendored vector snapshot.",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("tests/vectors/bip352/official/manifest.json"),
        help="Where to write the snapshot manifest.",
    )
    parser.add_argument(
        "--reference-root",
        type=Path,
        default=Path("tests/vectors/bip352/official/reference"),
        help="Where to write the vendored upstream reference bundle.",
    )
    args = parser.parse_args()

    try:
        commit = args.commit or resolve_branch_head()
        vector_url = raw_url(commit, VECTOR_RELATIVE_PATH)
        reference_url = raw_url(commit, REFERENCE_RELATIVE_PATH)
        payload = fetch_bytes(vector_url)
        vectors = validate_vectors(json.loads(payload.decode("utf-8")))
        reference_bundle = []
        for upstream_relative_path, local_relative_path in REFERENCE_BUNDLE_FILES:
            file_url = raw_url(commit, upstream_relative_path)
            file_payload = fetch_bytes(file_url)
            local_path = args.reference_root / Path(local_relative_path).relative_to("reference")
            reference_bundle.append(
                {
                    "upstream_relative_path": upstream_relative_path,
                    "path": str(local_path.relative_to(args.manifest.parent)),
                    "sha256": sha256_hex(file_payload),
                    "source": file_url,
                    "payload": file_payload,
                }
            )
    except VectorError as exc:
        print("error: {}".format(exc))
        return 2
    except Exception as exc:  # pragma: no cover - network failures are environment-specific
        print("error: {}".format(exc))
        return 2

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(payload)
    for item in reference_bundle:
        output_path = args.manifest.parent / item["path"]
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(item["payload"])

    manifest = {
        "fetched_at_utc": utc_now_iso(),
        "reference_bundle": [
            {
                "path": item["path"],
                "sha256": item["sha256"],
                "source": item["source"],
                "upstream_relative_path": item["upstream_relative_path"],
            }
            for item in reference_bundle
        ],
        "reference_source": reference_url,
        "sending_entry_count": sum(len(case["sending"]) for case in vectors),
        "receiving_entry_count": sum(len(case["receiving"]) for case in vectors),
        "sha256": sha256_hex(payload),
        "source": vector_url,
        "upstream_commit": commit,
        "vector_case_count": len(vectors),
    }
    write_json(args.manifest, manifest)

    print("pinned official vectors to {}".format(args.out))
    print("pinned upstream reference bundle to {}".format(args.reference_root))
    print("upstream commit: {}".format(commit))
    print("sha256: {}".format(manifest["sha256"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
