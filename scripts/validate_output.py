#!/usr/bin/env python3
"""Validate a worker output payload against the v1 output format."""

import argparse
import re
import struct
import sys
from pathlib import Path


class ValidationError(Exception):
    pass


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


def validate_output(buf: bytes) -> None:
    if len(buf) < 4:
        raise ValidationError("output too short")

    version = buf[0]
    status = buf[1]
    output_count = struct.unpack_from("<H", buf, 2)[0]

    if version != 1:
        raise ValidationError(f"unsupported version: {version}")

    if status != 0:
        if len(buf) != 4:
            raise ValidationError("non-ok status must have empty payload")
        return

    expected_len = 4 + output_count * (33 + 32)
    if len(buf) != expected_len:
        raise ValidationError(
            f"invalid payload length: expected {expected_len}, got {len(buf)}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a worker output payload")
    parser.add_argument("path", type=Path, help="Path to output file (hex or binary)")
    args = parser.parse_args()

    try:
        payload = read_payload(args.path)
        validate_output(payload)
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print("output payload is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
