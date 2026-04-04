#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Differential fuzz the native C++ bridge against the vendored BIP352 reference."""

from __future__ import annotations

import argparse
import copy
import json
import random
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Sequence, Tuple

from bip352_reference import load_reference_module
from bip352_semantics import derive_receive_semantics
from parse_case import CaseV2, InputEntryV2, parse_case, read_payload, serialize_case_v2


BASE_CASES = (
    "official_case_00_receive_00.hex",
    "official_case_19_receive_00.hex",
    "official_case_25_receive_00.hex",
    "official_case_26_receive_00.hex",
)
NUMS_H_HEX = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Differential fuzz the native bridge against the vendored BIP352 reference"
    )
    parser.add_argument("--cli", type=Path, default=Path("build/sp_differ_cli"))
    parser.add_argument("--iterations", type=int, default=10000)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--seed", type=int, default=352)
    parser.add_argument(
        "--vectors-dir",
        type=Path,
        default=Path("tests/vectors/bip352/derived/v2"),
    )
    parser.add_argument(
        "--reference-dir",
        type=Path,
        default=Path("tests/vectors/bip352/official/reference"),
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=Path("build/native_reference_fuzz_report.json"),
    )
    parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="Keep successful batch artifacts under build/native_reference_fuzz_work",
    )
    return parser.parse_args()


def _load_base_cases(vectors_dir: Path) -> List[Tuple[str, CaseV2]]:
    cases: List[Tuple[str, CaseV2]] = []
    for name in BASE_CASES:
        payload = read_payload(str(vectors_dir / name), "hex")
        parsed = parse_case(payload)
        if not isinstance(parsed, CaseV2):
            raise RuntimeError(f"{name} is not a v2 case")
        cases.append((name, parsed))
    return cases


def _random_scalar_bytes(reference_module, rng: random.Random) -> bytes:
    while True:
        candidate = rng.getrandbits(256).to_bytes(32, "big")
        try:
            reference_module.Scalar.from_bytes_checked(candidate)
            return candidate
        except Exception:
            continue


def _random_xonly_pubkey(reference_module, rng: random.Random) -> bytes:
    scalar = reference_module.Scalar.from_bytes_checked(_random_scalar_bytes(reference_module, rng))
    return (scalar * reference_module.G).to_bytes_xonly()


def _decode_compact_size(data: bytes, offset: int) -> Tuple[int, int]:
    first = data[offset]
    offset += 1
    if first < 253:
        return first, offset
    if first == 253:
        return int.from_bytes(data[offset : offset + 2], "little"), offset + 2
    if first == 254:
        return int.from_bytes(data[offset : offset + 4], "little"), offset + 4
    return int.from_bytes(data[offset : offset + 8], "little"), offset + 8


def _encode_compact_size(value: int) -> bytes:
    if value < 253:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    return b"\xff" + value.to_bytes(8, "little")


def _decode_witness_items(raw: bytes) -> List[bytes]:
    if not raw:
        return []
    offset = 0
    count, offset = _decode_compact_size(raw, offset)
    items: List[bytes] = []
    for _ in range(count):
        size, offset = _decode_compact_size(raw, offset)
        items.append(raw[offset : offset + size])
        offset += size
    return items


def _encode_witness_items(items: Sequence[bytes]) -> bytes:
    encoded = bytearray()
    encoded.extend(_encode_compact_size(len(items)))
    for item in items:
        encoded.extend(_encode_compact_size(len(item)))
        encoded.extend(item)
    return bytes(encoded)


def _mutate_outpoint(case: CaseV2, rng: random.Random) -> None:
    entry = rng.choice(case.inputs)
    txid = bytearray(entry.outpoint_txid)
    for _ in range(rng.randint(1, 4)):
        txid[rng.randrange(len(txid))] ^= rng.randrange(1, 256)
    entry.outpoint_txid = bytes(txid)
    if rng.random() < 0.5:
        entry.outpoint_vout ^= rng.randrange(1, 1 << 16)


def _mutate_outputs(case: CaseV2, reference_module, rng: random.Random) -> None:
    if not case.outputs_to_scan:
      return
    count = rng.randint(1, min(3, len(case.outputs_to_scan)))
    for _ in range(count):
        index = rng.randrange(len(case.outputs_to_scan))
        if rng.random() < 0.35:
            case.outputs_to_scan[index] = bytes(rng.choice(case.outputs_to_scan))
        else:
            case.outputs_to_scan[index] = _random_xonly_pubkey(reference_module, rng)


def _mutate_taproot_input(case: CaseV2, reference_module, rng: random.Random) -> None:
    entry = rng.choice(case.inputs)
    entry.input_type = 0x02
    entry.prevout_script_pubkey = b"\x51\x20" + _random_xonly_pubkey(reference_module, rng)
    internal_key = (
        bytes.fromhex(NUMS_H_HEX)
        if rng.random() < 0.5
        else _random_xonly_pubkey(reference_module, rng)
    )
    control_block = bytes([0xC0 | rng.randrange(2)]) + internal_key
    stack = [b"\x00", b"\x51", control_block]
    if rng.random() < 0.25:
        stack.append(b"\x50fuzz-annex")
    entry.script_sig = b""
    entry.txinwitness = _encode_witness_items(stack)


def _mutate_case(base_case: CaseV2, reference_module, rng: random.Random) -> CaseV2:
    case = copy.deepcopy(base_case)
    operation_count = rng.randint(1, 4)
    for _ in range(operation_count):
        selector = rng.random()
        if selector < 0.45:
            _mutate_outpoint(case, rng)
        elif selector < 0.8:
            _mutate_taproot_input(case, reference_module, rng)
        else:
            _mutate_outputs(case, reference_module, rng)
    return case


def _write_case_pair(
    case: CaseV2,
    case_path: Path,
    expected_path: Path,
    reference_module,
    source_id: str,
    detailed_outputs_available: bool,
) -> None:
    payload = serialize_case_v2(case)
    case_path.write_text(payload.hex() + "\n", encoding="utf-8")
    source = {
        "kind": "receive",
        "comment": "native-reference-fuzz",
        "case_index": 0,
        "entry_index": 0,
        "id": source_id,
    }
    expected = derive_receive_semantics(
        reference_module,
        case,
        source,
        detailed_outputs_available=detailed_outputs_available,
    )
    expected_path.write_text(json.dumps(expected, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run_batch(cli: Path, batch_dir: Path, case_paths: Sequence[Path], batch_index: int) -> None:
    report_path = batch_dir / f"report_{batch_index:04d}.json"
    cmd = [
        str(cli),
        "--suite-name",
        f"native-reference-fuzz-{batch_index:04d}",
        "--semantic-worker",
        "native",
        "--json-out",
        str(report_path),
    ]
    for case_path in case_paths:
        cmd.extend(["--case", str(case_path)])
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            "native/reference fuzz batch failed: batch={} rc={} stdout={} stderr={}".format(
                batch_index,
                result.returncode,
                result.stdout.strip(),
                result.stderr.strip(),
            )
        )


def main() -> int:
    args = _parse_args()
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    work_root = Path("build/native_reference_fuzz_work")
    work_root.mkdir(parents=True, exist_ok=True)

    reference_script = args.reference_dir / "reference.py"
    reference_module = load_reference_module(reference_script, args.reference_dir)
    base_cases = _load_base_cases(args.vectors_dir)
    rng = random.Random(args.seed)

    generated = 0
    attempts = 0
    batch_index = 0
    summary = {
        "status": "passed",
        "iterations": args.iterations,
        "batch_size": args.batch_size,
        "seed": args.seed,
        "batches": 0,
        "attempts": 0,
        "focus": [
            "lexicographically-smallest outpoint input_hash",
            "taproot script-path inputs",
            "NUMS_H internal-key skipping",
        ],
    }

    try:
        while generated < args.iterations:
            batch_dir = work_root / f"batch_{batch_index:04d}"
            if batch_dir.exists():
                shutil.rmtree(batch_dir)
            batch_dir.mkdir(parents=True)
            case_paths: List[Path] = []
            target_count = min(args.batch_size, args.iterations - generated)
            while len(case_paths) < target_count:
                attempts += 1
                base_name, base_case = rng.choice(base_cases)
                case = _mutate_case(base_case, reference_module, rng)
                detailed_outputs_available = (
                    len(case.outputs_to_scan) <= 128 and rng.random() < 0.75
                )
                source_id = f"native_reference_fuzz_{generated + len(case_paths):05d}"
                case_path = batch_dir / f"{source_id}.hex"
                expected_path = batch_dir / f"{source_id}.expected.json"
                try:
                    _write_case_pair(
                        case,
                        case_path,
                        expected_path,
                        reference_module,
                        source_id,
                        detailed_outputs_available,
                    )
                except Exception:
                    continue
                case_paths.append(case_path)
            _run_batch(args.cli, batch_dir, case_paths, batch_index)
            generated += len(case_paths)
            batch_index += 1
            if not args.keep_artifacts:
                shutil.rmtree(batch_dir)
        summary["batches"] = batch_index
        summary["attempts"] = attempts
        args.json_out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except Exception as exc:
        summary["status"] = "failed"
        summary["batches"] = batch_index
        summary["attempts"] = attempts
        summary["error"] = str(exc)
        args.json_out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"FAIL: {exc}", file=sys.stderr)
        print(f"  artifacts: {work_root}", file=sys.stderr)
        return 1

    print(f"OK: native/reference fuzz passed {generated} iteration(s)")
    print(f"  batches: {batch_index}")
    print(f"  attempts: {attempts}")
    print(f"  report: {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
