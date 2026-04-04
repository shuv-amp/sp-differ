#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Parse and validate a SP-DIFFER case file.

Supports v1 and v2 case formats plus hex-encoded files (default) or raw binary
payloads.
"""

import argparse
import re
import struct
import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple, Union


FLAG_NEGATIVE = 1 << 0
FLAG_INPUT_PRIVATE_KEYS = 1 << 1
FLAG_INPUT_PUBLIC_KEYS = 1 << 2
FLAG_PREVOUT_SCRIPT_PUBKEYS = 1 << 3
FLAG_SCRIPT_SIGS = 1 << 4
FLAG_TXINWITNESSES = 1 << 5
FLAG_RECIPIENT_GROUPS = 1 << 6
FLAG_OUTPUTS_TO_SCAN = 1 << 7
FLAG_RECEIVER_KEY_MATERIAL = 1 << 8

SUPPORTED_FLAGS_MASK_V1 = FLAG_NEGATIVE | FLAG_INPUT_PRIVATE_KEYS | FLAG_INPUT_PUBLIC_KEYS
SUPPORTED_FLAGS_MASK_V2 = (
    SUPPORTED_FLAGS_MASK_V1
    | FLAG_PREVOUT_SCRIPT_PUBKEYS
    | FLAG_SCRIPT_SIGS
    | FLAG_TXINWITNESSES
    | FLAG_RECIPIENT_GROUPS
    | FLAG_OUTPUTS_TO_SCAN
    | FLAG_RECEIVER_KEY_MATERIAL
)

INPUT_TYPES_V1 = {
    0x01: "P2WPKH",
    0x02: "P2TR keypath",
    0x03: "P2SH-P2WPKH",
}

INPUT_TYPES_V2 = {
    0x01: "P2WPKH",
    0x02: "P2TR keypath",
    0x03: "P2SH-P2WPKH",
    0x04: "P2PKH",
}


@dataclass
class CaseHeaderV1:
    version: int
    seed: int
    flags: int
    input_count: int
    output_count: int


@dataclass
class InputEntryV1:
    outpoint_txid: bytes
    outpoint_vout: int
    input_type: int
    privkey: Optional[bytes]
    pubkey: Optional[bytes]


@dataclass
class CaseV1:
    header: CaseHeaderV1
    inputs: List[InputEntryV1]
    scan_pubkey: bytes
    spend_pubkey: bytes
    labels: List[int]


@dataclass
class CaseHeaderV2:
    version: int
    seed: int
    flags: int
    input_count: int
    recipient_group_count: int
    scan_output_count: int
    label_count: int


@dataclass
class InputEntryV2:
    outpoint_txid: bytes
    outpoint_vout: int
    input_type: int
    prevout_script_pubkey: Optional[bytes]
    script_sig: Optional[bytes]
    txinwitness: Optional[bytes]
    privkey: Optional[bytes]
    pubkey: Optional[bytes]


@dataclass
class RecipientGroupV2:
    scan_pubkey: bytes
    spend_pubkey: bytes
    count: int


@dataclass
class ReceiverKeyMaterialV2:
    scan_privkey: Optional[bytes]
    spend_privkey: Optional[bytes]


@dataclass
class CaseV2:
    header: CaseHeaderV2
    inputs: List[InputEntryV2]
    recipient_groups: List[RecipientGroupV2]
    outputs_to_scan: List[bytes]
    receiver_keys: ReceiverKeyMaterialV2
    labels: List[int]


CaseValue = Union[CaseV1, CaseV2]


class ParseError(Exception):
    pass


def _read_u8(buf: bytes, off: int) -> Tuple[int, int]:
    if off + 1 > len(buf):
        raise ParseError("unexpected end of data")
    return buf[off], off + 1


def _read_u16(buf: bytes, off: int) -> Tuple[int, int]:
    if off + 2 > len(buf):
        raise ParseError("unexpected end of data")
    return struct.unpack_from("<H", buf, off)[0], off + 2


def _read_u32(buf: bytes, off: int) -> Tuple[int, int]:
    if off + 4 > len(buf):
        raise ParseError("unexpected end of data")
    return struct.unpack_from("<I", buf, off)[0], off + 4


def _read_u64(buf: bytes, off: int) -> Tuple[int, int]:
    if off + 8 > len(buf):
        raise ParseError("unexpected end of data")
    return struct.unpack_from("<Q", buf, off)[0], off + 8


def _read_bytes(buf: bytes, off: int, n: int) -> Tuple[bytes, int]:
    if off + n > len(buf):
        raise ParseError("unexpected end of data")
    return buf[off : off + n], off + n


def _read_var_bytes(buf: bytes, off: int) -> Tuple[bytes, int]:
    size, off = _read_u16(buf, off)
    return _read_bytes(buf, off, size)


def _write_u8(value: int) -> bytes:
    return struct.pack("<B", int(value))


def _write_u16(value: int) -> bytes:
    return struct.pack("<H", int(value))


def _write_u32(value: int) -> bytes:
    return struct.pack("<I", int(value))


def _write_u64(value: int) -> bytes:
    return struct.pack("<Q", int(value))


def _write_var_bytes(value: bytes) -> bytes:
    return _write_u16(len(value)) + value


def _parse_header_v1(buf: bytes, off: int) -> Tuple[CaseHeaderV1, int]:
    version, off = _read_u8(buf, off)
    seed, off = _read_u64(buf, off)
    flags, off = _read_u32(buf, off)
    input_count, off = _read_u16(buf, off)
    output_count, off = _read_u16(buf, off)
    return CaseHeaderV1(version, seed, flags, input_count, output_count), off


def _parse_header_v2(buf: bytes, off: int) -> Tuple[CaseHeaderV2, int]:
    version, off = _read_u8(buf, off)
    seed, off = _read_u64(buf, off)
    flags, off = _read_u32(buf, off)
    input_count, off = _read_u16(buf, off)
    recipient_group_count, off = _read_u16(buf, off)
    scan_output_count, off = _read_u16(buf, off)
    label_count, off = _read_u16(buf, off)
    return (
        CaseHeaderV2(version, seed, flags, input_count, recipient_group_count, scan_output_count, label_count),
        off,
    )


def _parse_inputs_v1(buf: bytes, off: int, header: CaseHeaderV1) -> Tuple[List[InputEntryV1], int]:
    inputs: List[InputEntryV1] = []
    has_priv = bool(header.flags & FLAG_INPUT_PRIVATE_KEYS)
    has_pub = bool(header.flags & FLAG_INPUT_PUBLIC_KEYS)

    for _ in range(header.input_count):
        outpoint_txid, off = _read_bytes(buf, off, 32)
        outpoint_vout, off = _read_u32(buf, off)
        input_type, off = _read_u8(buf, off)
        if input_type not in INPUT_TYPES_V1:
            raise ParseError(f"unknown input_type: 0x{input_type:02x}")

        privkey = None
        pubkey = None
        if has_priv:
            privkey, off = _read_bytes(buf, off, 32)
        if has_pub:
            pubkey, off = _read_bytes(buf, off, 33)
            if not _looks_like_compressed_pubkey(pubkey):
                raise ParseError("invalid public key encoding")

        inputs.append(InputEntryV1(outpoint_txid, outpoint_vout, input_type, privkey, pubkey))

    return inputs, off


def _parse_inputs_v2(buf: bytes, off: int, header: CaseHeaderV2) -> Tuple[List[InputEntryV2], int]:
    inputs: List[InputEntryV2] = []
    has_prevout_script_pubkeys = bool(header.flags & FLAG_PREVOUT_SCRIPT_PUBKEYS)
    has_script_sigs = bool(header.flags & FLAG_SCRIPT_SIGS)
    has_txinwitnesses = bool(header.flags & FLAG_TXINWITNESSES)
    has_priv = bool(header.flags & FLAG_INPUT_PRIVATE_KEYS)
    has_pub = bool(header.flags & FLAG_INPUT_PUBLIC_KEYS)

    for _ in range(header.input_count):
        outpoint_txid, off = _read_bytes(buf, off, 32)
        outpoint_vout, off = _read_u32(buf, off)
        input_type, off = _read_u8(buf, off)
        if input_type not in INPUT_TYPES_V2:
            raise ParseError(f"unknown input_type: 0x{input_type:02x}")

        prevout_script_pubkey = None
        script_sig = None
        txinwitness = None
        privkey = None
        pubkey = None
        if has_prevout_script_pubkeys:
            prevout_script_pubkey, off = _read_var_bytes(buf, off)
        if has_script_sigs:
            script_sig, off = _read_var_bytes(buf, off)
        if has_txinwitnesses:
            txinwitness, off = _read_var_bytes(buf, off)
        if has_priv:
            privkey, off = _read_bytes(buf, off, 32)
        if has_pub:
            pubkey, off = _read_bytes(buf, off, 33)
            if not _looks_like_compressed_pubkey(pubkey):
                raise ParseError("invalid public key encoding")

        inputs.append(
            InputEntryV2(
                outpoint_txid,
                outpoint_vout,
                input_type,
                prevout_script_pubkey,
                script_sig,
                txinwitness,
                privkey,
                pubkey,
            )
        )

    return inputs, off


def _parse_receiver_v1(buf: bytes, off: int) -> Tuple[bytes, bytes, List[int], int]:
    scan_pubkey, off = _read_bytes(buf, off, 33)
    spend_pubkey, off = _read_bytes(buf, off, 33)
    label_count, off = _read_u16(buf, off)

    labels = []
    for _ in range(label_count):
        label, off = _read_u32(buf, off)
        labels.append(label)

    return scan_pubkey, spend_pubkey, labels, off


def _parse_case_v1(buf: bytes) -> CaseV1:
    off = 0
    header, off = _parse_header_v1(buf, off)
    if header.version != 1:
        raise ParseError(f"unsupported version: {header.version}")
    if header.flags & ~SUPPORTED_FLAGS_MASK_V1:
        raise ParseError(f"unsupported flags: 0x{header.flags:08x}")

    inputs, off = _parse_inputs_v1(buf, off, header)
    scan_pubkey, spend_pubkey, labels, off = _parse_receiver_v1(buf, off)
    if not _looks_like_compressed_pubkey(scan_pubkey) or not _looks_like_compressed_pubkey(
        spend_pubkey
    ):
        raise ParseError("invalid receiver public key encoding")

    if off != len(buf):
        raise ParseError(f"trailing bytes: {len(buf) - off}")

    return CaseV1(header, inputs, scan_pubkey, spend_pubkey, labels)


def _parse_case_v2(buf: bytes) -> CaseV2:
    off = 0
    header, off = _parse_header_v2(buf, off)
    if header.version != 2:
        raise ParseError(f"unsupported version: {header.version}")
    if header.flags & ~SUPPORTED_FLAGS_MASK_V2:
        raise ParseError(f"unsupported flags: 0x{header.flags:08x}")

    has_recipient_groups = bool(header.flags & FLAG_RECIPIENT_GROUPS)
    has_outputs_to_scan = bool(header.flags & FLAG_OUTPUTS_TO_SCAN)
    has_receiver_key_material = bool(header.flags & FLAG_RECEIVER_KEY_MATERIAL)

    if not has_recipient_groups and header.recipient_group_count != 0:
        raise ParseError("unexpected recipient group count")
    if not has_outputs_to_scan and header.scan_output_count != 0:
        raise ParseError("unexpected scan output count")
    if not has_receiver_key_material and header.label_count != 0:
        raise ParseError("unexpected label count")

    inputs, off = _parse_inputs_v2(buf, off, header)

    recipient_groups: List[RecipientGroupV2] = []
    if has_recipient_groups:
        for _ in range(header.recipient_group_count):
            scan_pubkey, off = _read_bytes(buf, off, 33)
            spend_pubkey, off = _read_bytes(buf, off, 33)
            count, off = _read_u16(buf, off)
            if not _looks_like_compressed_pubkey(scan_pubkey) or not _looks_like_compressed_pubkey(
                spend_pubkey
            ):
                raise ParseError("invalid recipient public key encoding")
            if count == 0:
                raise ParseError("recipient count must be nonzero")
            recipient_groups.append(RecipientGroupV2(scan_pubkey, spend_pubkey, count))

    outputs_to_scan: List[bytes] = []
    if has_outputs_to_scan:
        for _ in range(header.scan_output_count):
            output_key, off = _read_bytes(buf, off, 32)
            outputs_to_scan.append(output_key)

    receiver_scan_privkey = None
    receiver_spend_privkey = None
    if has_receiver_key_material:
        receiver_scan_privkey, off = _read_bytes(buf, off, 32)
        receiver_spend_privkey, off = _read_bytes(buf, off, 32)

    labels = []
    for _ in range(header.label_count):
        label, off = _read_u32(buf, off)
        labels.append(label)

    if off != len(buf):
        raise ParseError(f"trailing bytes: {len(buf) - off}")

    return CaseV2(
        header,
        inputs,
        recipient_groups,
        outputs_to_scan,
        ReceiverKeyMaterialV2(receiver_scan_privkey, receiver_spend_privkey),
        labels,
    )


def _looks_like_compressed_pubkey(pubkey: bytes) -> bool:
    return len(pubkey) == 33 and pubkey[:1] in (b"\x02", b"\x03")


def parse_case(buf: bytes) -> CaseValue:
    version, _ = _read_u8(buf, 0)
    if version == 1:
        return _parse_case_v1(buf)
    if version == 2:
        return _parse_case_v2(buf)
    raise ParseError(f"unsupported version: {version}")


def serialize_case_v2(case: CaseV2) -> bytes:
    header = case.header
    if header.version != 2:
        raise ParseError(f"unsupported version: {header.version}")
    if header.flags & ~SUPPORTED_FLAGS_MASK_V2:
        raise ParseError(f"unsupported flags: 0x{header.flags:08x}")
    if header.input_count != len(case.inputs):
        raise ParseError("input_count/header mismatch")
    if header.recipient_group_count != len(case.recipient_groups):
        raise ParseError("recipient_group_count/header mismatch")
    if header.scan_output_count != len(case.outputs_to_scan):
        raise ParseError("scan_output_count/header mismatch")
    if header.label_count != len(case.labels):
        raise ParseError("label_count/header mismatch")

    has_prevout_script_pubkeys = bool(header.flags & FLAG_PREVOUT_SCRIPT_PUBKEYS)
    has_script_sigs = bool(header.flags & FLAG_SCRIPT_SIGS)
    has_txinwitnesses = bool(header.flags & FLAG_TXINWITNESSES)
    has_priv = bool(header.flags & FLAG_INPUT_PRIVATE_KEYS)
    has_pub = bool(header.flags & FLAG_INPUT_PUBLIC_KEYS)
    has_recipient_groups = bool(header.flags & FLAG_RECIPIENT_GROUPS)
    has_outputs_to_scan = bool(header.flags & FLAG_OUTPUTS_TO_SCAN)
    has_receiver_key_material = bool(header.flags & FLAG_RECEIVER_KEY_MATERIAL)

    parts = [
        _write_u8(header.version),
        _write_u64(header.seed),
        _write_u32(header.flags),
        _write_u16(header.input_count),
        _write_u16(header.recipient_group_count),
        _write_u16(header.scan_output_count),
        _write_u16(header.label_count),
    ]

    for entry in case.inputs:
        if len(entry.outpoint_txid) != 32:
            raise ParseError("invalid outpoint txid length")
        if entry.input_type not in INPUT_TYPES_V2:
            raise ParseError(f"unknown input_type: 0x{entry.input_type:02x}")

        parts.append(bytes(entry.outpoint_txid))
        parts.append(_write_u32(entry.outpoint_vout))
        parts.append(_write_u8(entry.input_type))

        if has_prevout_script_pubkeys:
            parts.append(_write_var_bytes(bytes(entry.prevout_script_pubkey or b"")))
        if has_script_sigs:
            parts.append(_write_var_bytes(bytes(entry.script_sig or b"")))
        if has_txinwitnesses:
            parts.append(_write_var_bytes(bytes(entry.txinwitness or b"")))
        if has_priv:
            if entry.privkey is None or len(entry.privkey) != 32:
                raise ParseError("missing or invalid input private key")
            parts.append(bytes(entry.privkey))
        if has_pub:
            if entry.pubkey is None or not _looks_like_compressed_pubkey(entry.pubkey):
                raise ParseError("missing or invalid input public key")
            parts.append(bytes(entry.pubkey))

    if has_recipient_groups:
        for group in case.recipient_groups:
            if not _looks_like_compressed_pubkey(group.scan_pubkey) or not _looks_like_compressed_pubkey(
                group.spend_pubkey
            ):
                raise ParseError("invalid recipient public key encoding")
            if group.count <= 0:
                raise ParseError("recipient count must be nonzero")
            parts.append(bytes(group.scan_pubkey))
            parts.append(bytes(group.spend_pubkey))
            parts.append(_write_u16(group.count))
    elif case.recipient_groups:
        raise ParseError("recipient groups present without header flag")

    if has_outputs_to_scan:
        for output_key in case.outputs_to_scan:
            if len(output_key) != 32:
                raise ParseError("invalid outputs_to_scan entry length")
            parts.append(bytes(output_key))
    elif case.outputs_to_scan:
        raise ParseError("outputs_to_scan present without header flag")

    if has_receiver_key_material:
        if case.receiver_keys.scan_privkey is None or len(case.receiver_keys.scan_privkey) != 32:
            raise ParseError("missing or invalid receiver scan_privkey")
        if case.receiver_keys.spend_privkey is None or len(case.receiver_keys.spend_privkey) != 32:
            raise ParseError("missing or invalid receiver spend_privkey")
        parts.append(bytes(case.receiver_keys.scan_privkey))
        parts.append(bytes(case.receiver_keys.spend_privkey))
    elif case.receiver_keys.scan_privkey is not None or case.receiver_keys.spend_privkey is not None:
        raise ParseError("receiver key material present without header flag")

    for label in case.labels:
        parts.append(_write_u32(label))

    return b"".join(parts)


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


def _print_v1(case: CaseV1) -> None:
    header = case.header
    flags = header.flags

    print("SP-DIFFER case v1")
    print(f"  seed: 0x{header.seed:x}")
    print(f"  flags: 0x{header.flags:08x}")
    print(f"  inputs: {header.input_count}")
    print(f"  outputs: {header.output_count}")
    print(f"  negative: {'yes' if flags & FLAG_NEGATIVE else 'no'}")
    print(f"  privkeys: {'yes' if flags & FLAG_INPUT_PRIVATE_KEYS else 'no'}")
    print(f"  pubkeys: {'yes' if flags & FLAG_INPUT_PUBLIC_KEYS else 'no'}")

    for idx, entry in enumerate(case.inputs):
        label = INPUT_TYPES_V1.get(entry.input_type, "unknown")
        print(f"  input[{idx}]: {label}, vout={entry.outpoint_vout}")

    print(f"  labels: {len(case.labels)}")


def _print_v2(case: CaseV2) -> None:
    header = case.header
    flags = header.flags

    print("SP-DIFFER case v2")
    print(f"  seed: 0x{header.seed:x}")
    print(f"  flags: 0x{header.flags:08x}")
    print(f"  inputs: {header.input_count}")
    print(f"  recipient groups: {header.recipient_group_count}")
    print(f"  outputs to scan: {header.scan_output_count}")
    print(f"  labels: {header.label_count}")
    print(f"  negative: {'yes' if flags & FLAG_NEGATIVE else 'no'}")
    print(f"  prevout scriptPubKeys: {'yes' if flags & FLAG_PREVOUT_SCRIPT_PUBKEYS else 'no'}")
    print(f"  scriptSigs: {'yes' if flags & FLAG_SCRIPT_SIGS else 'no'}")
    print(f"  txinwitnesses: {'yes' if flags & FLAG_TXINWITNESSES else 'no'}")
    print(f"  privkeys: {'yes' if flags & FLAG_INPUT_PRIVATE_KEYS else 'no'}")
    print(f"  pubkeys: {'yes' if flags & FLAG_INPUT_PUBLIC_KEYS else 'no'}")
    print(f"  receiver key material: {'yes' if flags & FLAG_RECEIVER_KEY_MATERIAL else 'no'}")

    for idx, entry in enumerate(case.inputs):
        label = INPUT_TYPES_V2.get(entry.input_type, "unknown")
        print(f"  input[{idx}]: {label}, vout={entry.outpoint_vout}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse and validate a SP-DIFFER case file")
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

    if isinstance(case, CaseV1):
        _print_v1(case)
    else:
        _print_v2(case)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
