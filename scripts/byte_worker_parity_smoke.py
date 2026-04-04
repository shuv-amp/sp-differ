#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check representative byte-worker parity through the published C ABI."""

import argparse
import sys
from ctypes import CDLL, POINTER, c_int, c_size_t, c_uint8, c_uint32
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _shared_lib_name(stem: str) -> str:
    if sys.platform == "darwin":
        return f"{stem}.dylib"
    if sys.platform.startswith("win"):
        return f"{stem}.dll"
    return f"{stem}.so"


def _default_cpp_lib() -> Path:
    return ROOT / "build" / _shared_lib_name("libsp_differ_worker")


def _default_rust_lib() -> Path:
    return ROOT / "build" / _shared_lib_name("libsp_differ_worker_rust")


def _build_v1_case(input_type: int) -> bytes:
    payload = bytearray()
    payload.append(1)  # version
    payload.extend((0).to_bytes(8, "little"))  # seed
    payload.extend((1 << 1).to_bytes(4, "little"))  # flags: private keys present
    payload.extend((1).to_bytes(2, "little"))  # input_count
    payload.extend((1).to_bytes(2, "little"))  # output_count
    payload.extend(bytes(32))  # txid
    payload.extend((0).to_bytes(4, "little"))  # vout
    payload.append(input_type)
    payload.extend(bytes.fromhex("00" * 31 + "01"))  # valid private key scalar
    payload.extend(b"\x02" + bytes(32))  # scan pubkey
    payload.extend(b"\x02" + bytes(32))  # spend pubkey
    payload.extend((0).to_bytes(2, "little"))  # label_count
    return bytes(payload)


def _run_worker(lib_path: Path, payload: bytes) -> bytes:
    lib = CDLL(str(lib_path.resolve()))
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
        raise RuntimeError(f"{lib_path} returned unexpected ABI version")

    output_ptr = POINTER(c_uint8)()
    output_len = c_size_t(0)
    input_buf = (c_uint8 * len(payload)).from_buffer_copy(payload)

    rc = lib.sp_differ_worker_run(input_buf, len(payload), output_ptr, output_len)
    if rc != 0:
        raise RuntimeError(f"{lib_path} returned nonzero run status {rc}")

    output = bytes(output_ptr[: output_len.value])
    lib.sp_differ_worker_free(output_ptr)
    return output


def _assert_status(output: bytes, expected_status: int, label: str) -> None:
    if len(output) != 4:
        raise RuntimeError(f"{label}: expected 4-byte worker output, got {len(output)}")
    if output[0] != 1:
        raise RuntimeError(f"{label}: unexpected output version {output[0]}")
    if output[1] != expected_status:
        raise RuntimeError(
            f"{label}: expected status {expected_status}, got {output[1]}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Byte-worker parity smoke test")
    parser.add_argument(
        "--cpp-lib",
        type=Path,
        default=_default_cpp_lib(),
        help="Path to the C++ byte worker shared library",
    )
    parser.add_argument(
        "--rust-lib",
        type=Path,
        default=_default_rust_lib(),
        help="Path to the Rust byte worker shared library",
    )
    args = parser.parse_args()

    for lib_path in (args.cpp_lib, args.rust_lib):
        if not lib_path.exists():
            print(f"FAIL: missing worker library {lib_path}", file=sys.stderr)
            return 2

    cases = [
        ("valid-p2tr-keypath", 0x02, 0),
        ("invalid-v1-p2pkh-marker", 0x04, 1),
    ]

    try:
        for label, input_type, expected_status in cases:
            payload = _build_v1_case(input_type)
            cpp_output = _run_worker(args.cpp_lib, payload)
            rust_output = _run_worker(args.rust_lib, payload)
            _assert_status(cpp_output, expected_status, f"{label} cpp")
            _assert_status(rust_output, expected_status, f"{label} rust")
            if cpp_output != rust_output:
                raise RuntimeError(
                    f"{label}: worker outputs diverged ({cpp_output.hex()} != {rust_output.hex()})"
                )
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2

    print("OK: byte-worker parity holds for representative v1 input-type cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
