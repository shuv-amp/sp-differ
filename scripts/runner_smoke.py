#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Minimal end-to-end smoke check for the worker interface."""

import argparse
import os
import re
import subprocess
import sys
import tempfile
from ctypes import CDLL, POINTER, c_int, c_size_t, c_uint8, c_uint32
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKER_CPP = ROOT / "workers" / "cpp" / "sp_differ_worker.cpp"
CASE_CPP = ROOT / "src" / "core" / "case.cpp"
KNOWN_STATUSES = {0, 1, 2, 3, 4, 5, 255}


def read_payload(path: Path) -> bytes:
    raw = path.read_bytes()
    if _looks_like_hex(raw):
        return bytes.fromhex(re.sub(rb"\s+", b"", raw).decode("ascii"))
    return raw


def _looks_like_hex(raw: bytes) -> bool:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return False
    return re.fullmatch(r"[0-9a-fA-F\s]+", text) is not None


def _shared_lib_name() -> str:
    if sys.platform == "darwin":
        return "libsp_differ_worker.dylib"
    if sys.platform.startswith("win"):
        return "sp_differ_worker.dll"
    return "libsp_differ_worker.so"


def _split_flags(raw: str) -> list[str]:
    return [flag for flag in raw.split() if flag]


def _resolve_secp256k1_flags() -> tuple[list[str], list[str]]:
    cflags_env = os.environ.get("SP_DIFFER_SECP256K1_CFLAGS", "")
    libs_env = os.environ.get("SP_DIFFER_SECP256K1_LIBS", "")

    cflags = _split_flags(cflags_env)
    libs = _split_flags(libs_env)
    if cflags and libs:
        return cflags, libs

    try:
        resolved_cflags = subprocess.check_output(
            ["pkg-config", "--cflags", "secp256k1"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        resolved_libs = subprocess.check_output(
            ["pkg-config", "--libs", "secp256k1"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        cflags = _split_flags(resolved_cflags)
        libs = _split_flags(resolved_libs)
    except (FileNotFoundError, subprocess.CalledProcessError):
        cflags = []
        libs = []

    if cflags and libs:
        return cflags, libs

    # Fallback for Homebrew installs where pkg-config cannot resolve secp256k1.pc.
    return ["-I/opt/homebrew/include"], ["-L/opt/homebrew/lib", "-lsecp256k1"]


def build_worker(out_path: Path) -> None:
    secp_cflags, secp_libs = _resolve_secp256k1_flags()
    cmd = [
        "c++",
        "-std=c++17",
        "-O2",
        "-fPIC",
        "-shared",
        "-o",
        str(out_path),
        str(WORKER_CPP),
        str(CASE_CPP),
        *secp_cflags,
        *secp_libs,
    ]
    subprocess.check_call(cmd)


def validate_output(buf: bytes) -> None:
    if len(buf) < 4:
        raise ValueError("output too short")

    version = buf[0]
    status = buf[1]
    output_count = buf[2] | (buf[3] << 8)

    if version != 1:
        raise ValueError(f"unsupported version: {version}")
    if status not in KNOWN_STATUSES:
        raise ValueError(f"unknown status: {status}")

    if status != 0:
        if len(buf) != 4:
            raise ValueError("non-ok status must have empty payload")
        return

    expected_len = 4 + output_count * (33 + 32)
    if len(buf) != expected_len:
        raise ValueError(f"invalid payload length: expected {expected_len}, got {len(buf)}")


def run_worker(payload: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as tmp_dir:
        lib_path = Path(tmp_dir) / _shared_lib_name()
        build_worker(lib_path)

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

        if lib.sp_differ_worker_api_version() != 1:
            raise RuntimeError("worker ABI version mismatch")

        output_ptr = POINTER(c_uint8)()
        output_len = c_size_t(0)
        input_buf = (c_uint8 * len(payload)).from_buffer_copy(payload)

        rc = lib.sp_differ_worker_run(input_buf, len(payload), output_ptr, output_len)
        if rc != 0:
            raise RuntimeError("worker run failed")

        out = bytes(output_ptr[: output_len.value])
        lib.sp_differ_worker_free(output_ptr)
        return out


def main() -> int:
    parser = argparse.ArgumentParser(description="End-to-end worker smoke check")
    parser.add_argument("case", type=Path, help="Path to case file (hex or binary)")
    args = parser.parse_args()

    payload = read_payload(args.case)

    try:
        out = run_worker(payload)
        validate_output(out)
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2

    print("OK: worker output valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
