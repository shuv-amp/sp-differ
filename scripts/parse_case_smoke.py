#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Focused smoke tests for the SP-DIFFER case parser."""

import struct
import sys
import tempfile
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import parse_case  # noqa: E402


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _expect_parse_error(action: Callable[[], object], expected: str) -> None:
    try:
        action()
    except parse_case.ParseError as exc:
        _require(expected in str(exc), f"expected {expected!r}, got {str(exc)!r}")
        return
    raise RuntimeError(f"expected ParseError containing {expected!r}")


def _fixture_payload(name: str) -> bytes:
    return parse_case.read_payload(str(ROOT / "tests" / "vectors" / name), "hex")


def _valid_fixture_smoke() -> None:
    v1 = parse_case.parse_case(_fixture_payload("example.hex"))
    _require(isinstance(v1, parse_case.CaseV1), "expected v1 fixture to parse as CaseV1")
    _require(v1.header.input_count == len(v1.inputs), "expected v1 input count to match")

    v2_payload = _fixture_payload("example_v2.hex")
    v2 = parse_case.parse_case(v2_payload)
    _require(isinstance(v2, parse_case.CaseV2), "expected v2 fixture to parse as CaseV2")
    _require(parse_case.serialize_case_v2(v2) == v2_payload, "expected lossless v2 round trip")


def _malformed_payload_smoke() -> None:
    v2_payload = _fixture_payload("example_v2.hex")

    _expect_parse_error(lambda: parse_case.parse_case(b""), "unexpected end of data")
    _expect_parse_error(lambda: parse_case.parse_case(b"\x03"), "unsupported version: 3")
    _expect_parse_error(
        lambda: parse_case.parse_case(v2_payload + b"\x00"),
        "trailing bytes: 1",
    )

    unsupported_flags = bytearray(v2_payload)
    struct.pack_into("<I", unsupported_flags, 9, 1 << 31)
    _expect_parse_error(
        lambda: parse_case.parse_case(bytes(unsupported_flags)),
        "unsupported flags: 0x80000000",
    )

    missing_recipient_flag = bytearray(v2_payload)
    flags = struct.unpack_from("<I", missing_recipient_flag, 9)[0]
    struct.pack_into(
        "<I",
        missing_recipient_flag,
        9,
        flags & ~parse_case.FLAG_RECIPIENT_GROUPS,
    )
    _expect_parse_error(
        lambda: parse_case.parse_case(bytes(missing_recipient_flag)),
        "unexpected recipient group count",
    )


def _input_format_smoke() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        path = Path(tmp_dir) / "payload"
        path.write_bytes(b"01")
        _require(parse_case.read_payload(str(path), "auto") == b"\x01", "expected auto hex decoding")
        _require(parse_case.read_payload(str(path), "bin") == b"01", "expected forced binary input")

        path.write_bytes(b"0g")
        _expect_parse_error(
            lambda: parse_case.read_payload(str(path), "hex"),
            "invalid hex encoding",
        )


def main() -> int:
    _valid_fixture_smoke()
    _malformed_payload_smoke()
    _input_format_smoke()
    print("OK: parse_case smoke tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
