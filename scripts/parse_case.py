#!/usr/bin/env python3
"""Parse and validate a SP-DIFFER v1 case file.

Supports hex-encoded files (default) or raw binary payloads.
"""

import argparse
import re
import struct
import sys
from dataclasses import dataclass
from typing import List

INPUT_TYPES = {
    0x01: "P2WPKH",
    0x02: "P2TR keypath",
    0x03: "P2SH-P2WPKH",
}


@dataclass
class CaseHeader:
    version: int
    seed: int
    flags: int
    input_count: int
    output_count: int


@dataclass
class InputEntry:
    outpoint_txid: bytes
    outpoint_vout: int
    input_type: int
    privkey: bytes | None
    pubkey: bytes | None


@dataclass
class Case:
    header: CaseHeader
    inputs: List[InputEntry]
    scan_pubkey: bytes
    spend_pubkey: bytes
    labels: List[int]


class ParseError(Exception):
    pass


def _read_u8(buf: bytes, off: int) -> tuple[int, int]:
    if off + 1 > len(buf):
        raise ParseError("unexpected end of data")
    return buf[off], off + 1


def _read_u16(buf: bytes, off: int) -> tuple[int, int]:
    if off + 2 > len(buf):
        raise ParseError("unexpected end of data")
    return struct.unpack_from("<H", buf, off)[0], off + 2


def _read_u32(buf: bytes, off: int) -> tuple[int, int]:
    if off + 4 > len(buf):
        raise ParseError("unexpected end of data")
    return struct.unpack_from("<I", buf, off)[0], off + 4


def _read_u64(buf: bytes, off: int) -> tuple[int, int]:
    if off + 8 > len(buf):
        raise ParseError("unexpected end of data")
    return struct.unpack_from("<Q", buf, off)[0], off + 8


def _read_bytes(buf: bytes, off: int, n: int) -> tuple[bytes, int]:
    if off + n > len(buf):
        raise ParseError("unexpected end of data")
    return buf[off : off + n], off + n


def _parse_header(buf: bytes, off: int) -> tuple[CaseHeader, int]:
    version, off = _read_u8(buf, off)
    seed, off = _read_u64(buf, off)
    flags, off = _read_u32(buf, off)
    input_count, off = _read_u16(buf, off)
    output_count, off = _read_u16(buf, off)
    return CaseHeader(version, seed, flags, input_count, output_count), off


def _parse_inputs(buf: bytes, off: int, header: CaseHeader) -> tuple[List[InputEntry], int]:
    inputs: List[InputEntry] = []
    has_priv = bool(header.flags & (1 << 1))
    has_pub = bool(header.flags & (1 << 2))

    for _ in range(header.input_count):
        outpoint_txid, off = _read_bytes(buf, off, 32)
        outpoint_vout, off = _read_u32(buf, off)
        input_type, off = _read_u8(buf, off)
        if input_type not in INPUT_TYPES:
            raise ParseError(f"unknown input_type: 0x{input_type:02x}")

        privkey = None
        pubkey = None
        if has_priv:
            privkey, off = _read_bytes(buf, off, 32)
        if has_pub:
            pubkey, off = _read_bytes(buf, off, 33)

        inputs.append(InputEntry(outpoint_txid, outpoint_vout, input_type, privkey, pubkey))

    return inputs, off


def _parse_receiver(buf: bytes, off: int) -> tuple[bytes, bytes, List[int], int]:
    scan_pubkey, off = _read_bytes(buf, off, 33)
    spend_pubkey, off = _read_bytes(buf, off, 33)
    label_count, off = _read_u16(buf, off)

    labels = []
    for _ in range(label_count):
        label, off = _read_u32(buf, off)
        labels.append(label)

    return scan_pubkey, spend_pubkey, labels, off


def parse_case(buf: bytes) -> Case:
    off = 0
    header, off = _parse_header(buf, off)
    if header.version != 1:
        raise ParseError(f"unsupported version: {header.version}")

    inputs, off = _parse_inputs(buf, off, header)
    scan_pubkey, spend_pubkey, labels, off = _parse_receiver(buf, off)

    if off != len(buf):
        raise ParseError(f"trailing bytes: {len(buf) - off}")

    return Case(header, inputs, scan_pubkey, spend_pubkey, labels)


def read_payload(path: str, fmt: str) -> bytes:
    raw = open(path, "rb").read()
    if fmt == "bin":
        return raw

    if fmt == "hex" or _looks_like_hex(raw):
        text = re.sub(rb"\s+", b"", raw)
        try:
            return bytes.fromhex(text.decode("ascii"))
        except ValueError as exc:
            raise ParseError("invalid hex encoding") from exc

    return raw


def _looks_like_hex(raw: bytes) -> bool:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return False
    return re.fullmatch(r"[0-9a-fA-F\s]+", text) is not None


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse and validate a SP-DIFFER v1 case file")
    parser.add_argument("path", help="Path to case file (hex or binary)")
    parser.add_argument(
        "--format",
        choices=["auto", "hex", "bin"],
        default="auto",
        help="Input format: auto, hex, or bin",
    )
    args = parser.parse_args()

    try:
        payload = read_payload(args.path, args.format)
        case = parse_case(payload)
    except ParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    header = case.header
    flags = header.flags
    has_priv = bool(flags & (1 << 1))
    has_pub = bool(flags & (1 << 2))

    print("SP-DIFFER case v1")
    print(f"  seed: 0x{header.seed:x}")
    print(f"  flags: 0x{header.flags:08x}")
    print(f"  inputs: {header.input_count}")
    print(f"  outputs: {header.output_count}")
    print(f"  privkeys: {'yes' if has_priv else 'no'}")
    print(f"  pubkeys: {'yes' if has_pub else 'no'}")

    for idx, entry in enumerate(case.inputs):
        label = INPUT_TYPES.get(entry.input_type, "unknown")
        print(f"  input[{idx}]: {label}, vout={entry.outpoint_vout}")

    print(f"  labels: {len(case.labels)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
