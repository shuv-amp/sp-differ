#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate tracked semantic error-surface fixtures and runtime cases."""

import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from ctypes import CDLL, POINTER, c_int, c_size_t, c_uint8, c_uint32
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from bip352_reference import load_reference_module
from semantic_contract import compare_semantic_results, validate_semantic_result


ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = ROOT / "build"
DEFAULT_MANIFEST = ROOT / "tests" / "error_surfaces" / "semantic" / "manifest.json"
DEFAULT_BRIDGE = ROOT / "scripts" / "semantic_bridge.py"
DEFAULT_COMPARE_BIN = ROOT / "build" / "sp_differ_compare"
FIXTURE_SRC = ROOT / "tests" / "fixtures" / "semantic_worker_smoke.cpp"
DEFAULT_REFERENCE = ROOT / "tests" / "vectors" / "bip352" / "official" / "reference" / "reference.py"
SEND_CASE = ROOT / "tests" / "vectors" / "bip352" / "derived" / "v2" / "official_case_00_send_00.hex"
RECEIVE_CASE = ROOT / "tests" / "vectors" / "bip352" / "derived" / "v2" / "official_case_00_receive_00.hex"
DEFAULT_JSON_OUT = BUILD_DIR / "semantic_error_surface_report.json"
DEFAULT_MARKDOWN_OUT = BUILD_DIR / "semantic_error_surface_report.md"
FIXTURE_CXXFLAGS = ("-std=c++17", "-O2", "-fPIC")
GENERATOR_COMPRESSED = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

STATUS_TO_BYTE_CODE = {
    "invalid_input": 1,
    "point_at_infinity": 2,
    "zero_scalar": 3,
    "invalid_pubkey": 4,
    "tweak_out_of_range": 5,
    "internal": 255,
}
BYTE_CODE_TO_STATUS = {value: key for key, value in STATUS_TO_BYTE_CODE.items()}


class SemanticErrorSurfaceError(Exception):
    pass


def _shared_lib_name(stem: str) -> str:
    if sys.platform == "darwin":
        return "lib{}.dylib".format(stem)
    if sys.platform.startswith("win"):
        return "{}.dll".format(stem)
    return "lib{}.so".format(stem)


def _default_cpp_worker_lib() -> Path:
    return ROOT / "build" / _shared_lib_name("sp_differ_worker")


def _default_rust_worker_lib() -> Path:
    return ROOT / "build" / _shared_lib_name("sp_differ_worker_rust")


def _resolve_within(root: Path, path: Path, *, require_exists: bool = True) -> Path:
    resolved_root = root.resolve()
    resolved_path = path.resolve()
    if resolved_path != resolved_root and resolved_root not in resolved_path.parents:
        raise SemanticErrorSurfaceError("{} escapes {}".format(path, root))
    if require_exists and not resolved_path.exists():
        raise SemanticErrorSurfaceError("path not found: {}".format(resolved_path))
    return resolved_path


def _resolve_build_output(path: Path) -> Path:
    candidate = path if path.is_absolute() else ROOT / path
    return _resolve_within(BUILD_DIR, candidate, require_exists=False)


def _fixture_compiler() -> str:
    compiler = shutil.which("c++")
    if compiler is None:
        raise SemanticErrorSurfaceError("c++ compiler not found in PATH")
    return compiler


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _render_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Semantic Error Surfaces",
        "",
        "- status: `{}`".format(report["status"]),
        "- synthetic_contract_cases: `{}`".format(report["counts"]["synthetic_contract_cases"]),
        "- compiled_compare_cases: `{}`".format(report["counts"]["compiled_compare_cases"]),
        "- byte_worker_runtime_cases: `{}`".format(report["counts"]["byte_worker_runtime_cases"]),
        "- covered_statuses: `{}`".format(", ".join(report["covered_statuses"])),
        "",
        "## Synthetic Fixtures",
        "",
    ]
    for item in report["synthetic_contract_cases"]:
        lines.append(
            "- `{}` kind=`{}` status=`{}` bridge=`{}` compare=`{}`".format(
                item["id"],
                item["kind"],
                item["semantic_status"],
                item["bridge_validation"],
                item["compiled_compare"],
            )
        )
    lines.extend(["", "## Byte Worker Runtime", ""])
    for item in report["byte_worker_runtime_cases"]:
        lines.append(
            "- `{}` status=`{}` cpp=`{}` rust=`{}`".format(
                item["id"],
                item["semantic_status"],
                item["cpp_status"],
                item["rust_status"],
            )
        )
    if report["failures"]:
        lines.extend(["", "## Failures", ""])
        for item in report["failures"]:
            lines.append("- `{}`: {}".format(item["id"], item["detail"]))
    lines.append("")
    return "\n".join(lines)


def _load_manifest(path: Path) -> Dict[str, Any]:
    raw = _load_json(path)
    if raw.get("semantic_error_surface_version") != 1:
        raise SemanticErrorSurfaceError("unsupported semantic error surface manifest version")
    if not isinstance(raw.get("cases"), list):
        raise SemanticErrorSurfaceError("manifest cases must be a list")
    if not isinstance(raw.get("byte_worker_cases"), list):
        raise SemanticErrorSurfaceError("manifest byte_worker_cases must be a list")
    return raw


def _run_command(
    command: Sequence[str], *, env: Optional[Dict[str, str]] = None, expected_rc: int = 0
) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        [str(part) for part in command],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != expected_rc:
        raise SemanticErrorSurfaceError(
            "command returned {} (expected {}): {}\nstdout: {}\nstderr: {}".format(
                proc.returncode,
                expected_rc,
                shlex.join([str(part) for part in command]),
                proc.stdout.strip(),
                proc.stderr.strip(),
            )
        )
    return proc


def _build_fixture(
    out_path: Path,
    response_env: str,
) -> None:
    command = [
        _fixture_compiler(),
        *FIXTURE_CXXFLAGS,
        "-shared",
        "-DSP_DIFFER_SEMANTIC_SMOKE_ENV={}".format(response_env),
        "-o",
        str(out_path),
        str(FIXTURE_SRC),
    ]
    _run_command(command)


def _validate_via_bridge(bridge_path: Path, fixture_path: Path, out_path: Path) -> Dict[str, Any]:
    _run_command(
        [
            sys.executable,
            str(bridge_path),
            "validate-result",
            "--input",
            str(fixture_path),
            "--json-out",
            str(out_path),
        ]
    )
    return _load_json(out_path)


def _run_compare_fixture(
    compare_bin: Path,
    left_lib: Path,
    right_lib: Path,
    fixture_path: Path,
    kind: str,
) -> None:
    case_path = SEND_CASE if kind == "send" else RECEIVE_CASE
    env = dict(os.environ)
    env["PYTHON"] = sys.executable
    env["SP_DIFFER_SEMANTIC_SMOKE_RESPONSE_LEFT"] = str(fixture_path)
    env["SP_DIFFER_SEMANTIC_SMOKE_RESPONSE_RIGHT"] = str(fixture_path)
    _run_command(
        [
            str(compare_bin),
            str(case_path),
            "--left",
            str(left_lib),
            "--right",
            str(right_lib),
        ],
        env=env,
        expected_rc=9,
    )


def _tagged_hash(tag: str, message: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode("utf-8")).digest()
    return hashlib.sha256(tag_hash + tag_hash + message).digest()


def _derive_tweak_cancel_spend_pubkey() -> str:
    reference_module = load_reference_module(DEFAULT_REFERENCE, DEFAULT_REFERENCE.parent)
    secret_key = reference_module.Scalar(1)
    input_pubkey_sum = secret_key * reference_module.G
    smallest_outpoint = bytes(32) + (0).to_bytes(4, "little")
    input_hash = reference_module.Scalar.from_bytes_checked(
        _tagged_hash("BIP0352/Inputs", smallest_outpoint + input_pubkey_sum.to_bytes_compressed())
    )
    shared_secret = input_hash * input_pubkey_sum
    tweak = reference_module.Scalar.from_bytes_checked(
        _tagged_hash("BIP0352/SharedSecret", shared_secret.to_bytes_compressed() + (0).to_bytes(4, "big"))
    )
    spend_pubkey = (-tweak) * reference_module.G
    return spend_pubkey.to_bytes_compressed().hex()


def _build_v1_case(
    *,
    flags: int,
    inputs: Sequence[Tuple[str, int, int, Optional[str], Optional[str]]],
    scan_pubkey: str,
    spend_pubkey: str,
    output_count: int = 1,
    labels: Sequence[int] = (),
) -> bytes:
    payload = bytearray()
    payload.append(1)
    payload.extend((0).to_bytes(8, "little"))
    payload.extend(int(flags).to_bytes(4, "little"))
    payload.extend(len(inputs).to_bytes(2, "little"))
    payload.extend(int(output_count).to_bytes(2, "little"))
    for outpoint_txid, outpoint_vout, input_type, privkey_hex, pubkey_hex in inputs:
        payload.extend(bytes.fromhex(outpoint_txid))
        payload.extend(int(outpoint_vout).to_bytes(4, "little"))
        payload.append(int(input_type))
        if flags & (1 << 1):
            if privkey_hex is None:
                raise SemanticErrorSurfaceError("missing privkey for v1 case")
            payload.extend(bytes.fromhex(privkey_hex))
        if flags & (1 << 2):
            if pubkey_hex is None:
                raise SemanticErrorSurfaceError("missing pubkey for v1 case")
            payload.extend(bytes.fromhex(pubkey_hex))
    payload.extend(bytes.fromhex(scan_pubkey))
    payload.extend(bytes.fromhex(spend_pubkey))
    payload.extend(len(labels).to_bytes(2, "little"))
    for label in labels:
        payload.extend(int(label).to_bytes(4, "little"))
    return bytes(payload)


def _build_byte_worker_payload(builder: str) -> bytes:
    valid_privkey = "00" * 31 + "01"
    if builder == "pubkey_mismatch":
        return _build_v1_case(
            flags=(1 << 1) | (1 << 2),
            inputs=[("00" * 32, 0, 0x01, valid_privkey, "02" + "00" * 32)],
            scan_pubkey=GENERATOR_COMPRESSED,
            spend_pubkey=GENERATOR_COMPRESSED,
        )
    if builder == "invalid_scan_pubkey":
        return _build_v1_case(
            flags=(1 << 1),
            inputs=[("00" * 32, 0, 0x01, valid_privkey, None)],
            scan_pubkey="02" + "00" * 32,
            spend_pubkey=GENERATOR_COMPRESSED,
        )
    if builder == "tweak_cancels_spend_pubkey":
        return _build_v1_case(
            flags=(1 << 1),
            inputs=[("00" * 32, 0, 0x01, valid_privkey, None)],
            scan_pubkey=GENERATOR_COMPRESSED,
            spend_pubkey=_derive_tweak_cancel_spend_pubkey(),
        )
    raise SemanticErrorSurfaceError("unknown byte worker builder: {}".format(builder))


def _run_byte_worker(lib_path: Path, payload: bytes) -> bytes:
    if not lib_path.is_file():
        raise SemanticErrorSurfaceError("byte worker library not found: {}".format(lib_path))
    lib = CDLL(str(lib_path))
    lib.sp_differ_worker_api_version.restype = c_uint32
    lib.sp_differ_worker_run.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        POINTER(POINTER(c_uint8)),
        POINTER(c_size_t),
    ]
    lib.sp_differ_worker_run.restype = c_int
    lib.sp_differ_worker_free.argtypes = [POINTER(c_uint8)]

    version = int(lib.sp_differ_worker_api_version())
    if version != 1:
        raise SemanticErrorSurfaceError(
            "unexpected byte worker ABI version {} for {}".format(version, lib_path)
        )

    output_ptr = POINTER(c_uint8)()
    output_len = c_size_t(0)
    input_buf = (c_uint8 * len(payload)).from_buffer_copy(payload)
    rc = lib.sp_differ_worker_run(input_buf, len(payload), output_ptr, output_len)
    if rc != 0:
        raise SemanticErrorSurfaceError(
            "byte worker returned nonzero run status {} for {}".format(rc, lib_path)
        )
    try:
        return bytes(output_ptr[: output_len.value])
    finally:
        lib.sp_differ_worker_free(output_ptr)


def _decode_byte_worker_status(payload: bytes) -> str:
    if len(payload) != 4:
        raise SemanticErrorSurfaceError("unexpected byte worker payload length {}".format(len(payload)))
    if payload[0] != 1:
        raise SemanticErrorSurfaceError("unexpected byte worker output version {}".format(payload[0]))
    status = int(payload[1])
    if status not in BYTE_CODE_TO_STATUS:
        raise SemanticErrorSurfaceError("unknown byte worker status {}".format(status))
    if status != 0 and payload[2:] != b"\x00\x00":
        raise SemanticErrorSurfaceError("non-ok byte worker payload must not include outputs")
    return BYTE_CODE_TO_STATUS[status]


def _run_synthetic_cases(
    manifest_path: Path,
    manifest: Dict[str, Any],
    bridge_path: Path,
    compare_bin: Optional[Path],
    *,
    skip_compiled_compare: bool,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]]]:
    results: List[Dict[str, Any]] = []
    failures: List[Dict[str, str]] = []

    with tempfile.TemporaryDirectory(prefix="sp_differ_semantic_error_surfaces_") as tmp_dir:
        tmp_root = Path(tmp_dir)
        left_lib = tmp_root / _shared_lib_name("semantic_error_surface_left")
        right_lib = tmp_root / _shared_lib_name("semantic_error_surface_right")
        if not skip_compiled_compare:
            if compare_bin is None or not compare_bin.is_file():
                raise SemanticErrorSurfaceError("compare binary not found: {}".format(compare_bin))
            _build_fixture(left_lib, "SP_DIFFER_SEMANTIC_SMOKE_RESPONSE_LEFT")
            _build_fixture(right_lib, "SP_DIFFER_SEMANTIC_SMOKE_RESPONSE_RIGHT")

        for entry in manifest["cases"]:
            case_id = entry["id"]
            fixture_path = _resolve_within(manifest_path.parent, manifest_path.parent / entry["path"])
            try:
                fixture = _load_json(fixture_path)
                canonical_python = validate_semantic_result(fixture)
                if canonical_python["semantic_status"] != entry["semantic_status"]:
                    raise SemanticErrorSurfaceError(
                        "{} canonical semantic_status {} != manifest {}".format(
                            case_id, canonical_python["semantic_status"], entry["semantic_status"]
                        )
                    )

                bridge_out = tmp_root / "{}_canonical.json".format(case_id)
                canonical_bridge = _validate_via_bridge(bridge_path, fixture_path, bridge_out)
                if canonical_bridge != canonical_python:
                    raise SemanticErrorSurfaceError(
                        "{} bridge canonicalization diverged from Python contract".format(case_id)
                    )

                mutated = deepcopy(canonical_python)
                mutated["semantic_status"] = "ok"
                mismatch_errors = compare_semantic_results(canonical_python, mutated)
                if "field mismatch: semantic_status" not in mismatch_errors:
                    raise SemanticErrorSurfaceError(
                        "{} did not trigger semantic_status mismatch under compare".format(case_id)
                    )

                compiled_compare = "skipped"
                if not skip_compiled_compare:
                    _run_compare_fixture(
                        compare_bin,
                        left_lib,
                        right_lib,
                        fixture_path,
                        entry["kind"],
                    )
                    compiled_compare = "passed"

                results.append(
                    {
                        "id": case_id,
                        "kind": entry["kind"],
                        "semantic_status": entry["semantic_status"],
                        "fixture_path": str(fixture_path),
                        "bridge_validation": "passed",
                        "compiled_compare": compiled_compare,
                        "compare_mismatch_errors": mismatch_errors,
                    }
                )
            except Exception as exc:
                failures.append({"id": case_id, "detail": str(exc)})
                results.append(
                    {
                        "id": case_id,
                        "kind": entry.get("kind"),
                        "semantic_status": entry.get("semantic_status"),
                        "fixture_path": str(fixture_path),
                        "bridge_validation": "failed",
                        "compiled_compare": "failed",
                    }
                )
    return results, failures


def _run_byte_worker_cases(
    manifest: Dict[str, Any],
    *,
    cpp_worker_lib: Path,
    rust_worker_lib: Path,
    skip_byte_workers: bool,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]]]:
    results: List[Dict[str, Any]] = []
    failures: List[Dict[str, str]] = []

    for entry in manifest["byte_worker_cases"]:
        case_id = entry["id"]
        if skip_byte_workers:
            results.append(
                {
                    "id": case_id,
                    "semantic_status": entry["semantic_status"],
                    "cpp_status": "skipped",
                    "rust_status": "skipped",
                }
            )
            continue
        try:
            payload = _build_byte_worker_payload(entry["builder"])
            cpp_status = _decode_byte_worker_status(_run_byte_worker(cpp_worker_lib, payload))
            rust_status = _decode_byte_worker_status(_run_byte_worker(rust_worker_lib, payload))
            expected = entry["semantic_status"]
            if cpp_status != expected:
                raise SemanticErrorSurfaceError(
                    "{} C++ worker returned {} (expected {})".format(case_id, cpp_status, expected)
                )
            if rust_status != expected:
                raise SemanticErrorSurfaceError(
                    "{} Rust worker returned {} (expected {})".format(case_id, rust_status, expected)
                )
            results.append(
                {
                    "id": case_id,
                    "semantic_status": expected,
                    "cpp_status": cpp_status,
                    "rust_status": rust_status,
                }
            )
        except Exception as exc:
            failures.append({"id": case_id, "detail": str(exc)})
            results.append(
                {
                    "id": case_id,
                    "semantic_status": entry["semantic_status"],
                    "cpp_status": "failed",
                    "rust_status": "failed",
                }
            )
    return results, failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate tracked semantic error surfaces")
    parser.add_argument(
        "--skip-compiled-compare",
        action="store_true",
        help="Skip the compiled compare-path check for synthetic fixtures",
    )
    parser.add_argument(
        "--skip-byte-workers",
        action="store_true",
        help="Skip the deterministic byte-worker runtime cases",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=DEFAULT_JSON_OUT.relative_to(ROOT),
        help="Machine-readable report path",
    )
    parser.add_argument(
        "--markdown-out",
        type=Path,
        default=DEFAULT_MARKDOWN_OUT.relative_to(ROOT),
        help="Markdown report path",
    )
    args = parser.parse_args()

    try:
        manifest_path = _resolve_within(ROOT, DEFAULT_MANIFEST)
        bridge_path = _resolve_within(ROOT, DEFAULT_BRIDGE)
        compare_bin = _resolve_within(ROOT, DEFAULT_COMPARE_BIN)
        cpp_worker_lib = _resolve_within(ROOT, _default_cpp_worker_lib())
        rust_worker_lib = _resolve_within(ROOT, _default_rust_worker_lib())
        json_out = _resolve_build_output(args.json_out)
        markdown_out = _resolve_build_output(args.markdown_out)

        manifest = _load_manifest(manifest_path)
        synthetic_results, synthetic_failures = _run_synthetic_cases(
            manifest_path,
            manifest,
            bridge_path,
            compare_bin,
            skip_compiled_compare=args.skip_compiled_compare,
        )
        byte_worker_results, byte_worker_failures = _run_byte_worker_cases(
            manifest,
            cpp_worker_lib=cpp_worker_lib,
            rust_worker_lib=rust_worker_lib,
            skip_byte_workers=args.skip_byte_workers,
        )
    except Exception as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2

    failures = synthetic_failures + byte_worker_failures
    covered_statuses = sorted(
        {
            item["semantic_status"] for item in manifest["cases"]
        }
        | {
            item["semantic_status"] for item in manifest["byte_worker_cases"]
        }
    )
    report = {
        "status": "passed" if not failures else "failed",
        "manifest": str(manifest_path),
        "covered_statuses": covered_statuses,
        "counts": {
            "synthetic_contract_cases": len(synthetic_results),
            "compiled_compare_cases": 0
            if args.skip_compiled_compare
            else len(synthetic_results),
            "byte_worker_runtime_cases": 0
            if args.skip_byte_workers
            else len(byte_worker_results),
            "failure_count": len(failures),
        },
        "synthetic_contract_cases": synthetic_results,
        "byte_worker_runtime_cases": byte_worker_results,
        "failures": failures,
    }
    _write_json(json_out, report)
    markdown_out.parent.mkdir(parents=True, exist_ok=True)
    markdown_out.write_text(_render_markdown(report) + "\n", encoding="utf-8")

    print("semantic error surfaces {}".format(report["status"]))
    print("  covered statuses: {}".format(", ".join(covered_statuses)))
    print("  synthetic fixtures: {}".format(len(synthetic_results)))
    print(
        "  byte worker runtime cases: {}".format(
            0 if args.skip_byte_workers else len(byte_worker_results)
        )
    )
    print("  failures: {}".format(len(failures)))
    print("  wrote report: {}".format(json_out))
    print("  wrote markdown: {}".format(markdown_out))
    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
