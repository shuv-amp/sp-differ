#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate a deterministic semantic-worker fuzz corpus."""

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from bip352_vectors import write_json
from parse_case import CaseV2, parse_case
from semantic_adapter import build_semantic_request
from semantic_contract import validate_semantic_result


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DERIVED_MANIFEST = ROOT / "tests" / "vectors" / "bip352" / "derived" / "v2" / "manifest.json"
DEFAULT_REGRESSION_MANIFEST = ROOT / "tests" / "regressions" / "semantic" / "manifest.json"
DEFAULT_CORPUS_ROOT = ROOT / "fuzz" / "corpus" / "semantic_worker"


class SemanticFuzzCorpusError(Exception):
    pass


def _read_case_v2(case_path: Path) -> CaseV2:
    parsed = parse_case(bytes.fromhex(case_path.read_text(encoding="ascii").strip()))
    if not isinstance(parsed, CaseV2):
        raise SemanticFuzzCorpusError("{} is not a v2 case".format(case_path))
    return parsed


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _canonical_json_bytes(payload: Dict[str, Any]) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _build_valid_seed_entries(
    derived_manifest_path: Path, regression_manifest_path: Path
) -> Tuple[List[Dict[str, Any]], Dict[str, bytes]]:
    entries: List[Dict[str, Any]] = []
    files: Dict[str, bytes] = {}
    seen_ids = set()

    derived_manifest = _load_json(derived_manifest_path)
    for item in derived_manifest.get("cases", []):
        case_path = derived_manifest_path.parent / item["path"]
        expectation_path = derived_manifest_path.parent / item["expectation_path"]
        expected = validate_semantic_result(_load_json(expectation_path))
        expectation_hints = None
        if item["kind"] == "receive":
            expectation_hints = {
                "detailed_outputs_required": bool(expected["detailed_outputs_available"])
            }
        request = build_semantic_request(
            item["kind"],
            _read_case_v2(case_path),
            expected["source"],
            expectation_hints=expectation_hints,
        )
        relpath = "valid/{}.json".format(item["id"])
        files[relpath] = _canonical_json_bytes(request)
        entries.append(
            {
                "id": item["id"],
                "kind": item["kind"],
                "path": relpath,
                "source": "derived-v2",
                "source_case_path": str(case_path.relative_to(ROOT)),
            }
        )
        seen_ids.add(item["id"])

    regression_manifest = _load_json(regression_manifest_path)
    for item in regression_manifest.get("cases", []):
        request_path = regression_manifest_path.parent / item["request_path"]
        request = build_semantic_request(
            item["kind"],
            _read_case_v2(regression_manifest_path.parent / item["path"]),
            item["source"],
            expectation_hints=None,
        )
        request = _load_json(request_path) if request_path.exists() else request
        relpath = "valid/regression_{}.json".format(item["id"])
        if item["id"] in seen_ids:
            continue
        files[relpath] = _canonical_json_bytes(request)
        entries.append(
            {
                "id": item["id"],
                "kind": item["kind"],
                "path": relpath,
                "source": "semantic-regression",
                "source_case_path": str((regression_manifest_path.parent / item["path"]).relative_to(ROOT)),
            }
        )
        seen_ids.add(item["id"])

    entries.sort(key=lambda item: item["id"])
    return entries, files


def _build_invalid_seed_entries(valid_files: Dict[str, bytes]) -> Tuple[List[Dict[str, Any]], Dict[str, bytes]]:
    sample_request = None
    for relpath in sorted(valid_files):
        if relpath.endswith(".json"):
            sample_request = json.loads(valid_files[relpath].decode("utf-8"))
            break
    if sample_request is None:
        raise SemanticFuzzCorpusError("cannot build invalid seeds without at least one valid request")

    wrong_version = dict(sample_request)
    wrong_version["semantic_adapter_request_version"] = 999

    missing_kind = dict(sample_request)
    missing_kind.pop("kind", None)

    invalid_hex = json.loads(json.dumps(sample_request))
    invalid_hex["inputs"][0]["outpoint_txid"] = "zz" * 32

    wrong_network = dict(sample_request)
    wrong_network["network"] = "signet"

    scalar_json = "[]\n".encode("utf-8")
    truncated_json = b'{"semantic_adapter_request_version":1'
    malformed_utf8 = bytes([0xFF, 0xFE, 0xFD, 0x00])

    invalid_specs = [
        ("invalid/empty_input.bin", b"", "empty payload"),
        ("invalid/bad_utf8.bin", malformed_utf8, "non-UTF8 payload"),
        ("invalid/truncated_json.bin", truncated_json, "truncated JSON object"),
        ("invalid/non_object_json.bin", scalar_json, "JSON value that is not an object"),
        ("invalid/wrong_version.json", _canonical_json_bytes(wrong_version), "unsupported request version"),
        ("invalid/missing_kind.json", _canonical_json_bytes(missing_kind), "missing kind field"),
        ("invalid/invalid_hex.json", _canonical_json_bytes(invalid_hex), "invalid hex field"),
        ("invalid/wrong_network.json", _canonical_json_bytes(wrong_network), "unknown network field"),
    ]

    entries = []
    files: Dict[str, bytes] = {}
    for relpath, payload, description in invalid_specs:
        files[relpath] = payload
        entries.append(
            {
                "id": Path(relpath).stem,
                "path": relpath,
                "description": description,
            }
        )
    return entries, files


def _expected_layout(
    derived_manifest_path: Path, regression_manifest_path: Path
) -> Tuple[Dict[str, Any], Dict[str, bytes]]:
    valid_entries, valid_files = _build_valid_seed_entries(
        derived_manifest_path, regression_manifest_path
    )
    invalid_entries, invalid_files = _build_invalid_seed_entries(valid_files)
    manifest = {
        "semantic_worker_corpus_version": 1,
        "generated_from": {
            "derived_manifest": str(derived_manifest_path.relative_to(ROOT)),
            "regression_manifest": str(regression_manifest_path.relative_to(ROOT)),
        },
        "valid": valid_entries,
        "invalid": invalid_entries,
    }
    files = {"manifest.json": _canonical_json_bytes(manifest)}
    files.update(valid_files)
    files.update(invalid_files)
    return manifest, files


def _check_files(root: Path, files: Dict[str, bytes]) -> None:
    expected_paths = {root / relpath for relpath in files}
    actual_paths = {
        path
        for path in root.rglob("*")
        if path.is_file()
    }
    extra = sorted(path for path in actual_paths - expected_paths if path.name != "README.md")
    missing = sorted(path for path in expected_paths - actual_paths)
    if extra:
        raise SemanticFuzzCorpusError(
            "unexpected corpus files: {}".format(", ".join(str(path.relative_to(root)) for path in extra))
        )
    if missing:
        raise SemanticFuzzCorpusError(
            "missing corpus files: {}".format(", ".join(str(path.relative_to(root)) for path in missing))
        )
    for relpath, expected in files.items():
        path = root / relpath
        if path.read_bytes() != expected:
            raise SemanticFuzzCorpusError("corpus drift: {}".format(relpath))


def _write_files(root: Path, files: Dict[str, bytes]) -> None:
    valid_dir = root / "valid"
    invalid_dir = root / "invalid"
    if valid_dir.exists():
        shutil.rmtree(valid_dir)
    if invalid_dir.exists():
        shutil.rmtree(invalid_dir)
    for relpath, payload in files.items():
        path = root / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate semantic-worker fuzz corpus")
    parser.add_argument(
        "--derived-manifest",
        type=Path,
        default=DEFAULT_DERIVED_MANIFEST,
        help="Path to the derived v2 manifest",
    )
    parser.add_argument(
        "--regression-manifest",
        type=Path,
        default=DEFAULT_REGRESSION_MANIFEST,
        help="Path to the semantic regression manifest",
    )
    parser.add_argument(
        "--corpus-root",
        type=Path,
        default=DEFAULT_CORPUS_ROOT,
        help="Target corpus root directory",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify the checked-in corpus instead of writing it",
    )
    args = parser.parse_args()

    try:
        manifest, files = _expected_layout(args.derived_manifest, args.regression_manifest)
        if args.check:
            _check_files(args.corpus_root, files)
            print("semantic fuzz corpus OK")
        else:
            _write_files(args.corpus_root, files)
            print("semantic fuzz corpus regenerated")
        print("  root: {}".format(args.corpus_root))
        print("  valid seeds: {}".format(len(manifest["valid"])))
        print("  invalid seeds: {}".format(len(manifest["invalid"])))
    except Exception as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
