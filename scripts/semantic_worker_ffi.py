#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Execute a semantic worker shared library via the semantic C ABI."""

import argparse
import json
import sys
from ctypes import CDLL, POINTER, byref, c_int, c_size_t, c_uint8, c_uint32
from pathlib import Path


SEMANTIC_WORKER_API_VERSION = 1


class SemanticWorkerFfiError(Exception):
    pass


def load_semantic_worker(lib_path: Path):
    if not lib_path.is_file():
        raise SemanticWorkerFfiError("shared library not found: {}".format(lib_path))
    lib = CDLL(str(lib_path))
    lib.sp_differ_semantic_worker_api_version.argtypes = []
    lib.sp_differ_semantic_worker_api_version.restype = c_uint32
    lib.sp_differ_semantic_worker_run.argtypes = [
        POINTER(c_uint8),
        c_size_t,
        POINTER(POINTER(c_uint8)),
        POINTER(c_size_t),
    ]
    lib.sp_differ_semantic_worker_run.restype = c_int
    lib.sp_differ_semantic_worker_free.argtypes = [POINTER(c_uint8)]
    version = int(lib.sp_differ_semantic_worker_api_version())
    if version != SEMANTIC_WORKER_API_VERSION:
        raise SemanticWorkerFfiError(
            "semantic worker ABI version mismatch: expected {}, got {}".format(
                SEMANTIC_WORKER_API_VERSION, version
            )
        )
    return lib


def invoke_loaded_semantic_worker(lib, request_bytes: bytes):
    output_ptr = POINTER(c_uint8)()
    output_len = c_size_t(0)

    if request_bytes:
        input_buf = (c_uint8 * len(request_bytes)).from_buffer_copy(request_bytes)
        input_ptr = input_buf
        input_len = len(request_bytes)
    else:
        input_ptr = POINTER(c_uint8)()
        input_len = 0

    rc = lib.sp_differ_semantic_worker_run(input_ptr, input_len, byref(output_ptr), byref(output_len))
    if rc != 0:
        return int(rc), None
    if not output_ptr:
        raise SemanticWorkerFfiError("semantic worker returned no output buffer")

    try:
        return 0, bytes(output_ptr[: output_len.value])
    finally:
        lib.sp_differ_semantic_worker_free(output_ptr)


def invoke_semantic_worker(lib_path: Path, request_bytes: bytes):
    lib = load_semantic_worker(lib_path)
    return invoke_loaded_semantic_worker(lib, request_bytes)


def run_semantic_worker(lib_path: Path, request_bytes: bytes) -> bytes:
    rc, output = invoke_semantic_worker(lib_path, request_bytes)
    if rc != 0:
        raise SemanticWorkerFfiError(
            "semantic worker run failed with status {}".format(rc)
        )
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Execute a semantic worker shared library")
    parser.add_argument(
        "--worker-lib",
        type=Path,
        required=True,
        help="Path to semantic worker shared library",
    )
    args = parser.parse_args()

    try:
        request = json.load(sys.stdin)
        response = run_semantic_worker(
            args.worker_lib,
            json.dumps(request, sort_keys=True).encode("utf-8"),
        )
        json.loads(response.decode("utf-8"))
    except Exception as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2

    sys.stdout.buffer.write(response)
    if not response.endswith(b"\n"):
        sys.stdout.buffer.write(b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
