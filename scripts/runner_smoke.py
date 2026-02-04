#!/usr/bin/env python3
"""Minimal end-to-end smoke check for the worker interface."""

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from ctypes import CDLL, POINTER, c_size_t, c_uint8, c_uint32


ROOT = Path(__file__).resolve().parents[1]
WORKER_CPP = ROOT / "workers" / "cpp" / "sp_differ_worker.cpp"


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


def build_worker(out_path: Path) -> None:
    cmd = [
        "c++",
        "-std=c++17",
        "-O2",
        "-fPIC",
        "-shared",
        "-o",
        str(out_path),
        str(WORKER_CPP),
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
        lib.sp_differ_worker_run.restype = c_uint8
        lib.sp_differ_worker_free.argtypes = [POINTER(c_uint8)]

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
