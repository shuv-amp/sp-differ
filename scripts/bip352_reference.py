#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Helpers for the vendored upstream BIP352 reference bundle."""

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Dict, Tuple

from bip352_vectors import sha256_hex, validate_vectors


def verify_reference_manifest(
    manifest_path: Path, vectors_path: Path
) -> Tuple[Dict[str, Any], Dict[str, Any], Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    raw_vectors = vectors_path.read_bytes()
    actual_sha256 = sha256_hex(raw_vectors)
    expected_sha256 = manifest.get("sha256")
    if expected_sha256 != actual_sha256:
        raise RuntimeError(
            "vector snapshot sha256 mismatch: expected {}, got {}".format(
                expected_sha256, actual_sha256
            )
        )

    reference_bundle = manifest.get("reference_bundle")
    if not isinstance(reference_bundle, list) or not reference_bundle:
        raise RuntimeError("manifest missing reference_bundle entries")

    verified_files = []
    manifest_dir = manifest_path.parent
    for item in reference_bundle:
        if not isinstance(item, dict):
            raise RuntimeError("invalid reference bundle entry")
        path = item.get("path")
        expected_file_sha256 = item.get("sha256")
        if not isinstance(path, str) or not isinstance(expected_file_sha256, str):
            raise RuntimeError("invalid reference bundle manifest fields")
        file_path = manifest_dir / path
        actual_file_sha256 = sha256_hex(file_path.read_bytes())
        if expected_file_sha256 != actual_file_sha256:
            raise RuntimeError(
                "reference bundle sha256 mismatch for {}: expected {}, got {}".format(
                    file_path, expected_file_sha256, actual_file_sha256
                )
            )
        verified_files.append(path)

    vectors = validate_vectors(json.loads(raw_vectors.decode("utf-8")))
    verification = {
        "snapshot_sha256": actual_sha256,
        "verified_reference_file_count": len(verified_files),
        "verified_reference_files": verified_files,
    }
    return manifest, verification, vectors


def load_reference_module(reference_script: Path, reference_dir: Path):
    sys.path.insert(0, str(reference_dir))
    spec = importlib.util.spec_from_file_location(
        "bip352_upstream_reference", reference_script
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load vendored upstream reference module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
