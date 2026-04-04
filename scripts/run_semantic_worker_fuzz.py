#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Deterministic fuzz runner for the semantic worker ABI."""

import argparse
import functools
import json
import random
import shlex
import shutil
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from bip352_reference import load_reference_module
from bip352_semantics import derive_receive_semantics, derive_sender_semantics
from bip352_vectors import write_json
from parse_case import ParseError, serialize_case_v2
from semantic_adapter import (
    SemanticAdapterError,
    case_from_semantic_request,
    validate_semantic_request,
)
from semantic_contract import (
    SemanticContractError,
    compare_semantic_results,
    validate_semantic_result,
)
from semantic_fuzz_minimizer import (
    SemanticFuzzMinimizerError,
    canonical_semantic_request_bytes,
    minimize_raw_payload,
    minimize_structured_request,
)
from semantic_worker_ffi import (
    SemanticWorkerFfiError,
    invoke_loaded_semantic_worker,
    load_semantic_worker,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS_ROOT = ROOT / "fuzz" / "corpus" / "semantic_worker"
DEFAULT_DICTIONARY = ROOT / "fuzz" / "dictionaries" / "semantic_request.dict"
DEFAULT_REFERENCE = ROOT / "tests" / "vectors" / "bip352" / "official" / "reference" / "reference.py"


class SemanticWorkerFuzzError(Exception):
    pass


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _canonical_request_bytes(payload: Dict[str, Any]) -> bytes:
    return canonical_semantic_request_bytes(payload)


def _random_bytes(rng: random.Random, length: int) -> bytes:
    return bytes(rng.getrandbits(8) for _ in range(length))


def _random_hex(rng: random.Random, byte_length: int) -> str:
    return _random_bytes(rng, byte_length).hex()


@functools.lru_cache(maxsize=1)
def _load_keygen_reference_module():
    return _load_reference_module()


def _random_valid_scalar_bytes(rng: random.Random) -> bytes:
    reference_module = _load_keygen_reference_module()
    while True:
        candidate = _random_bytes(rng, 32)
        try:
            reference_module.Scalar.from_bytes_checked(candidate)
            return candidate
        except Exception:
            continue


def _random_compressed_pubkey_hex(rng: random.Random) -> str:
    reference_module = _load_keygen_reference_module()
    scalar = reference_module.Scalar.from_bytes_checked(_random_valid_scalar_bytes(rng))
    return (scalar * reference_module.G).to_bytes_compressed().hex()


def _random_xonly_pubkey_hex(rng: random.Random) -> str:
    reference_module = _load_keygen_reference_module()
    scalar = reference_module.Scalar.from_bytes_checked(_random_valid_scalar_bytes(rng))
    return (scalar * reference_module.G).to_bytes_xonly().hex()


def _random_valid_secret_hex(rng: random.Random) -> str:
    return _random_valid_scalar_bytes(rng).hex()


def _load_dictionary_tokens(path: Path) -> List[bytes]:
    if not path.exists():
        return []
    tokens: List[bytes] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith('"') and line.endswith('"'):
            tokens.append(bytes(line[1:-1], "utf-8").decode("unicode_escape").encode("utf-8"))
        else:
            tokens.append(line.encode("utf-8"))
    return tokens


def _load_reference_module():
    return load_reference_module(DEFAULT_REFERENCE, DEFAULT_REFERENCE.parent)


def _run_reference(reference_module, request: Dict[str, Any]) -> Tuple[str, Optional[Dict[str, Any]], Optional[str]]:
    try:
        normalized_request = validate_semantic_request(request)
        case = case_from_semantic_request(normalized_request)
        if normalized_request["kind"] == "send":
            result = derive_sender_semantics(reference_module, case, normalized_request["source"])
        else:
            detailed_outputs_available = True
            hints = normalized_request.get("expectation_hints") or {}
            if "detailed_outputs_required" in hints:
                detailed_outputs_available = bool(hints["detailed_outputs_required"])
            result = derive_receive_semantics(
                reference_module,
                case,
                normalized_request["source"],
                detailed_outputs_available=detailed_outputs_available,
            )
        return "success", validate_semantic_result(result), None
    except Exception as exc:
        return "error", None, str(exc)


def _run_worker_raw(lib, request_bytes: bytes) -> Dict[str, Any]:
    try:
        rc, output = invoke_loaded_semantic_worker(lib, request_bytes)
    except Exception as exc:
        return {"outcome": "ffi_error", "error": str(exc), "raw_output": None, "result": None}
    if rc != 0:
        return {"outcome": "error", "error": "status {}".format(rc), "raw_output": None, "result": None}
    try:
        decoded = json.loads(output.decode("utf-8"))
    except Exception as exc:
        return {
            "outcome": "invalid_json",
            "error": str(exc),
            "raw_output": output,
            "result": None,
        }
    try:
        result = validate_semantic_result(decoded)
    except Exception as exc:
        return {
            "outcome": "invalid_contract",
            "error": str(exc),
            "raw_output": output,
            "result": None,
        }
    return {"outcome": "success", "error": None, "raw_output": output, "result": result}


def _slugify(value: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in value.lower()).strip("_")


def _worker_label(worker_lib: Path) -> str:
    label = worker_lib.stem
    if label.startswith("lib"):
        label = label[3:]
    return label.replace("_", "-")


def _request_case_hex(request: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    try:
        case = case_from_semantic_request(request, preserve_declared_flags=False)
        return serialize_case_v2(case).hex(), None
    except (ParseError, SemanticAdapterError, ValueError) as exc:
        return None, str(exc)


def _structured_failure_observation(
    reference_outcome: str,
    reference_result: Optional[Dict[str, Any]],
    reference_error: Optional[str],
    worker_result: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    if reference_outcome == "success" and worker_result["outcome"] == "success":
        errors = sorted(compare_semantic_results(reference_result, worker_result["result"]))
        if not errors:
            return None
        return {
            "failure_class": "semantic_mismatch",
            "signature": {
                "class": "semantic_mismatch",
                "errors": errors,
            },
            "errors": errors,
            "error_summary": "; ".join(errors),
            "reference_outcome": reference_outcome,
            "reference_result": reference_result,
            "reference_error": None,
            "worker_result": worker_result,
        }
    if reference_outcome == "error" and worker_result["outcome"] == "error":
        return None

    signature: Dict[str, Any] = {
        "class": "outcome_mismatch",
        "reference_outcome": reference_outcome,
        "worker_outcome": worker_result["outcome"],
    }
    if reference_outcome == "success" and reference_result is not None:
        signature["reference_semantic_status"] = reference_result["semantic_status"]
    if worker_result["outcome"] == "success" and worker_result["result"] is not None:
        signature["worker_semantic_status"] = worker_result["result"]["semantic_status"]

    errors = [
        "reference outcome {} vs worker outcome {}".format(
            reference_outcome, worker_result["outcome"]
        )
    ]
    return {
        "failure_class": "outcome_mismatch",
        "signature": signature,
        "errors": errors,
        "error_summary": errors[0],
        "reference_outcome": reference_outcome,
        "reference_result": reference_result,
        "reference_error": reference_error,
        "worker_result": worker_result,
    }


def _raw_failure_observation(worker_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if worker_result["outcome"] in ("success", "error"):
        return None
    error = worker_result["error"] or worker_result["outcome"]
    return {
        "failure_class": "worker_contract_error",
        "signature": {
            "class": "worker_outcome",
            "worker_outcome": worker_result["outcome"],
        },
        "errors": [error],
        "error_summary": error,
        "worker_result": worker_result,
    }


def _write_minimized_structured_artifact(
    failure_dir: Path,
    worker_lib: Path,
    failure_summary: Dict[str, Any],
    original_input_bytes: bytes,
    minimization: Dict[str, Any],
) -> Dict[str, Any]:
    minimized_dir = failure_dir / "minimized"
    minimized_dir.mkdir(parents=True, exist_ok=True)

    request = minimization["request"]
    observation = minimization["observation"]
    worker_result = observation["worker_result"]
    input_bytes = _canonical_request_bytes(request)
    input_path = minimized_dir / "input.bin"
    request_path = minimized_dir / "request.json"
    expected_path = minimized_dir / "expected.json"
    actual_path = minimized_dir / "actual.json"
    summary_path = minimized_dir / "summary.json"
    replay_path = minimized_dir / "replay.sh"
    promote_path = minimized_dir / "promote.sh"

    input_path.write_bytes(input_bytes)
    write_json(request_path, request)
    if observation["reference_result"] is not None:
        write_json(expected_path, observation["reference_result"])
    if worker_result.get("result") is not None:
        write_json(actual_path, worker_result["result"])
    if worker_result.get("raw_output") is not None:
        (minimized_dir / "worker_output.bin").write_bytes(worker_result["raw_output"])
    if observation.get("reference_error") is not None:
        (minimized_dir / "reference_error.txt").write_text(
            observation["reference_error"] + "\n", encoding="utf-8"
        )
    if worker_result.get("error") is not None:
        (minimized_dir / "worker_error.txt").write_text(
            worker_result["error"] + "\n", encoding="utf-8"
        )

    case_hex, case_error = _request_case_hex(request)
    if case_hex is not None:
        (minimized_dir / "case.hex").write_text(case_hex + "\n", encoding="ascii")
    elif case_error is not None:
        (minimized_dir / "case_error.txt").write_text(case_error + "\n", encoding="utf-8")

    replay_cmd = [
        "python3",
        "scripts/run_semantic_worker_fuzz.py",
        "--worker-lib",
        str(worker_lib),
        "--replay-input",
        str(input_path),
    ]
    replay_path.write_text(
        "#!/bin/sh\nset -eu\n{}\n".format(shlex.join(replay_cmd)),
        encoding="utf-8",
    )
    replay_path.chmod(0o755)

    minimized_summary: Dict[str, Any] = {
        "kind": "structured",
        "status": "reduced" if len(input_bytes) < len(original_input_bytes) else "unchanged",
        "failure_id": failure_summary["id"],
        "worker_lib": str(worker_lib),
        "failure_class": observation["failure_class"],
        "signature": observation["signature"],
        "errors": observation["errors"],
        "original_payload_bytes": len(original_input_bytes),
        "minimized_payload_bytes": len(input_bytes),
        "stats": minimization["stats"],
        "repro_cmd": shlex.join(replay_cmd),
    }

    intake_cmd = None
    bundle_dir = None
    if case_hex is not None and observation["reference_result"] is not None:
        bundle_dir = minimized_dir / "regression_bundle"
        bundle_dir.mkdir(parents=True, exist_ok=True)
        shutil_summary = {
            "id": failure_summary["id"],
            "adapter_name": "semantic-worker-fuzz-{}".format(_worker_label(worker_lib)),
            "errors": observation["errors"],
            "repro_cmd": shlex.join(replay_cmd),
        }
        write_json(bundle_dir / "summary.json", shutil_summary)
        write_json(bundle_dir / "request.json", request)
        write_json(bundle_dir / "expected.json", observation["reference_result"])
        if worker_result.get("result") is not None:
            write_json(bundle_dir / "actual.json", worker_result["result"])
        (bundle_dir / "case.hex").write_text(case_hex + "\n", encoding="ascii")

        intake_cmd = [
            "python3",
            "scripts/intake_semantic_regressions.py",
            "--artifact-dir",
            str(bundle_dir),
        ]
        promote_path.write_text(
            "#!/bin/sh\nset -eu\n{}\n".format(shlex.join(intake_cmd)),
            encoding="utf-8",
        )
        promote_path.chmod(0o755)
        minimized_summary["intake_cmd"] = shlex.join(intake_cmd)
        minimized_summary["regression_bundle_dir"] = str(bundle_dir)

    write_json(summary_path, minimized_summary)
    return {
        "minimized_dir": str(minimized_dir),
        "minimized_summary_path": str(summary_path),
        "minimized_payload_bytes": len(input_bytes),
        "intake_cmd": None if intake_cmd is None else shlex.join(intake_cmd),
        "regression_bundle_dir": None if bundle_dir is None else str(bundle_dir),
    }


def _write_minimized_raw_artifact(
    failure_dir: Path,
    worker_lib: Path,
    failure_summary: Dict[str, Any],
    original_input_bytes: bytes,
    minimization: Dict[str, Any],
) -> Dict[str, Any]:
    minimized_dir = failure_dir / "minimized"
    minimized_dir.mkdir(parents=True, exist_ok=True)

    payload = minimization["payload"]
    observation = minimization["observation"]
    worker_result = observation["worker_result"]
    input_path = minimized_dir / "input.bin"
    summary_path = minimized_dir / "summary.json"
    replay_path = minimized_dir / "replay.sh"

    input_path.write_bytes(payload)
    if worker_result.get("raw_output") is not None:
        (minimized_dir / "worker_output.bin").write_bytes(worker_result["raw_output"])
    if worker_result.get("error") is not None:
        (minimized_dir / "worker_error.txt").write_text(
            worker_result["error"] + "\n", encoding="utf-8"
        )

    replay_cmd = [
        "python3",
        "scripts/run_semantic_worker_fuzz.py",
        "--worker-lib",
        str(worker_lib),
        "--replay-input",
        str(input_path),
    ]
    replay_path.write_text(
        "#!/bin/sh\nset -eu\n{}\n".format(shlex.join(replay_cmd)),
        encoding="utf-8",
    )
    replay_path.chmod(0o755)

    write_json(
        summary_path,
        {
            "kind": "raw",
            "status": "reduced" if len(payload) < len(original_input_bytes) else "unchanged",
            "failure_id": failure_summary["id"],
            "worker_lib": str(worker_lib),
            "failure_class": observation["failure_class"],
            "signature": observation["signature"],
            "errors": observation["errors"],
            "original_payload_bytes": len(original_input_bytes),
            "minimized_payload_bytes": len(payload),
            "stats": minimization["stats"],
            "repro_cmd": shlex.join(replay_cmd),
        },
    )
    return {
        "minimized_dir": str(minimized_dir),
        "minimized_summary_path": str(summary_path),
        "minimized_payload_bytes": len(payload),
        "intake_cmd": None,
        "regression_bundle_dir": None,
    }


def _mutate_valid_request(rng: random.Random, request: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    base = json.loads(json.dumps(request))
    mutators: List[Tuple[str, Callable[[Dict[str, Any]], None]]] = []

    def shuffle_inputs(payload: Dict[str, Any]) -> None:
        rng.shuffle(payload["inputs"])

    def duplicate_input(payload: Dict[str, Any]) -> None:
        payload["inputs"].append(json.loads(json.dumps(rng.choice(payload["inputs"]))))

    def mutate_outpoint(payload: Dict[str, Any]) -> None:
        item = rng.choice(payload["inputs"])
        item["outpoint_txid"] = _random_hex(rng, 32)
        item["outpoint_vout"] = rng.randrange(0, 8)

    def mutate_input_type(payload: Dict[str, Any]) -> None:
        item = rng.choice(payload["inputs"])
        item["input_type"] = rng.choice(["p2wpkh", "p2tr", "p2sh-p2wpkh", "p2pkh"])

    def clear_optional_pubkey_field(payload: Dict[str, Any]) -> None:
        item = rng.choice(payload["inputs"])
        item["pubkey"] = None

    def randomize_input_privkey(payload: Dict[str, Any]) -> None:
        item = rng.choice(payload["inputs"])
        if item.get("privkey") is not None:
            item["privkey"] = _random_valid_secret_hex(rng)

    def mutate_prevout_script(payload: Dict[str, Any]) -> None:
        item = rng.choice(payload["inputs"])
        item["prevout_script_pubkey"] = _random_hex(rng, rng.randrange(20, 38))

    def toggle_hint(payload: Dict[str, Any]) -> None:
        if payload["kind"] == "receive":
            hints = dict(payload.get("expectation_hints") or {})
            hints["detailed_outputs_required"] = not hints.get("detailed_outputs_required", True)
            payload["expectation_hints"] = hints

    mutators.extend(
        [
            ("shuffle_inputs", shuffle_inputs),
            ("duplicate_input", duplicate_input),
            ("mutate_outpoint", mutate_outpoint),
            ("mutate_input_type", mutate_input_type),
            ("clear_optional_pubkey_field", clear_optional_pubkey_field),
            ("randomize_input_privkey", randomize_input_privkey),
            ("mutate_prevout_script", mutate_prevout_script),
            ("toggle_hint", toggle_hint),
        ]
    )

    if base["kind"] == "send":
        def duplicate_recipient_group(payload: Dict[str, Any]) -> None:
            payload["recipient_groups"].append(
                json.loads(json.dumps(rng.choice(payload["recipient_groups"])))
            )

        def mutate_recipient_keys(payload: Dict[str, Any]) -> None:
            group = rng.choice(payload["recipient_groups"])
            group["scan_pubkey"] = _random_compressed_pubkey_hex(rng)
            group["spend_pubkey"] = _random_compressed_pubkey_hex(rng)

        def mutate_recipient_count(payload: Dict[str, Any]) -> None:
            group = rng.choice(payload["recipient_groups"])
            group["count"] = rng.randrange(1, 5)

        mutators.extend(
            [
                ("duplicate_recipient_group", duplicate_recipient_group),
                ("mutate_recipient_keys", mutate_recipient_keys),
                ("mutate_recipient_count", mutate_recipient_count),
            ]
        )
    else:
        def append_output(payload: Dict[str, Any]) -> None:
            payload["outputs_to_scan"].append(_random_xonly_pubkey_hex(rng))

        def mutate_output(payload: Dict[str, Any]) -> None:
            payload["outputs_to_scan"][rng.randrange(len(payload["outputs_to_scan"]))] = _random_xonly_pubkey_hex(rng)

        def mutate_receiver_keys(payload: Dict[str, Any]) -> None:
            payload["receiver_keys"]["scan_privkey"] = _random_valid_secret_hex(rng)
            payload["receiver_keys"]["spend_privkey"] = _random_valid_secret_hex(rng)

        def mutate_labels(payload: Dict[str, Any]) -> None:
            labels = list(payload["labels"])
            labels.append(rng.randrange(0, 16))
            payload["labels"] = labels

        mutators.extend(
            [
                ("append_output", append_output),
                ("mutate_output", mutate_output),
                ("mutate_receiver_keys", mutate_receiver_keys),
                ("mutate_labels", mutate_labels),
            ]
        )

    for _ in range(32):
        candidate = json.loads(json.dumps(base))
        name, mutator = rng.choice(mutators)
        mutator(candidate)
        try:
            return validate_semantic_request(candidate), name
        except SemanticAdapterError:
            continue
    raise SemanticWorkerFuzzError("unable to produce a valid structured mutation")


def _mutate_bytes(
    rng: random.Random, payload: bytes, dictionary_tokens: Sequence[bytes], max_payload_bytes: int
) -> Tuple[bytes, str]:
    if not payload:
        payload = b"{}"

    def flip_byte(data: bytes) -> bytes:
        index = rng.randrange(len(data))
        mutated = bytearray(data)
        mutated[index] ^= 1 << rng.randrange(0, 8)
        return bytes(mutated)

    def truncate(data: bytes) -> bytes:
        if len(data) == 1:
            return data[:0]
        return data[: rng.randrange(0, len(data))]

    def delete_slice(data: bytes) -> bytes:
        start = rng.randrange(len(data))
        end = min(len(data), start + rng.randrange(1, min(16, len(data) - start) + 1))
        return data[:start] + data[end:]

    def duplicate_slice(data: bytes) -> bytes:
        start = rng.randrange(len(data))
        end = min(len(data), start + rng.randrange(1, min(16, len(data) - start) + 1))
        return data[:end] + data[start:end] + data[end:]

    def insert_random(data: bytes) -> bytes:
        start = rng.randrange(len(data) + 1)
        return data[:start] + _random_bytes(rng, rng.randrange(1, 8)) + data[start:]

    def insert_token(data: bytes) -> bytes:
        token = rng.choice(dictionary_tokens) if dictionary_tokens else b'"kind"'
        start = rng.randrange(len(data) + 1)
        return data[:start] + token + data[start:]

    operations = [
        ("flip_byte", flip_byte),
        ("truncate", truncate),
        ("delete_slice", delete_slice),
        ("duplicate_slice", duplicate_slice),
        ("insert_random", insert_random),
        ("insert_token", insert_token),
    ]
    name, operation = rng.choice(operations)
    mutated = operation(payload)
    if len(mutated) > max_payload_bytes:
        mutated = mutated[:max_payload_bytes]
    return mutated, name


def _write_failure_artifact(
    artifact_root: Path,
    lane: str,
    index: int,
    worker_lib: Path,
    summary: Dict[str, Any],
    input_bytes: bytes,
    reference_result: Optional[Dict[str, Any]],
    reference_error: Optional[str],
    worker_result: Dict[str, Any],
) -> Path:
    failure_dir = artifact_root / "{:04d}_{}".format(index, lane)
    failure_dir.mkdir(parents=True, exist_ok=True)
    input_path = failure_dir / "input.bin"
    summary_path = failure_dir / "summary.json"
    replay_path = failure_dir / "replay.sh"
    input_path.write_bytes(input_bytes)
    write_json(summary_path, summary)
    replay_path.write_text(
        "#!/bin/sh\nset -eu\npython3 scripts/run_semantic_worker_fuzz.py --worker-lib {} --replay-input {}\n".format(
            worker_lib, input_path
        ),
        encoding="utf-8",
    )
    replay_path.chmod(0o755)

    try:
        request = json.loads(input_bytes.decode("utf-8"))
        if isinstance(request, dict):
            write_json(failure_dir / "request.json", request)
            case_hex, case_error = _request_case_hex(request)
            if case_hex is not None:
                (failure_dir / "case.hex").write_text(case_hex + "\n", encoding="ascii")
            elif case_error is not None:
                (failure_dir / "case_error.txt").write_text(case_error + "\n", encoding="utf-8")
    except Exception:
        pass
    if reference_result is not None:
        write_json(failure_dir / "reference.json", reference_result)
        write_json(failure_dir / "expected.json", reference_result)
    if reference_error is not None:
        (failure_dir / "reference_error.txt").write_text(reference_error + "\n", encoding="utf-8")
    if worker_result.get("raw_output") is not None:
        (failure_dir / "worker_output.bin").write_bytes(worker_result["raw_output"])
    if worker_result.get("result") is not None:
        write_json(failure_dir / "actual.json", worker_result["result"])
    if worker_result.get("error") is not None:
        (failure_dir / "worker_error.txt").write_text(worker_result["error"] + "\n", encoding="utf-8")
    return failure_dir


def _render_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Semantic Worker Fuzz Report",
        "",
        "- worker: `{}`".format(report["worker_lib"]),
        "- seed: `{}`".format(report["seed"]),
        "- structured_iterations: `{}`".format(report["structured_iterations"]),
        "- raw_iterations: `{}`".format(report["raw_iterations"]),
        "- valid_seed_count: `{}`".format(report["valid_seed_count"]),
        "- invalid_seed_count: `{}`".format(report["invalid_seed_count"]),
        "- failures: `{}`".format(report["failure_count"]),
        "",
    ]
    if not report["failures"]:
        lines.append("No failures.")
        return "\n".join(lines)
    lines.extend(["## Failures", ""])
    for failure in report["failures"]:
        lines.append("### `{}`".format(failure["id"]))
        lines.append("")
        lines.append("- lane: `{}`".format(failure["lane"]))
        lines.append("- error: `{}`".format(failure["error"]))
        if failure.get("artifact_dir"):
            lines.append("- artifact_dir: `{}`".format(failure["artifact_dir"]))
        minimization = failure.get("minimization")
        if isinstance(minimization, dict):
            lines.append("- minimized_dir: `{}`".format(minimization.get("minimized_dir")))
            if minimization.get("intake_cmd"):
                lines.append("- promote: `{}`".format(minimization["intake_cmd"]))
        if failure.get("minimization_error"):
            lines.append("- minimization_error: `{}`".format(failure["minimization_error"]))
        lines.append("")
    return "\n".join(lines)


def _load_corpus_manifest(corpus_root: Path) -> Dict[str, Any]:
    manifest_path = corpus_root / "manifest.json"
    if not manifest_path.exists():
        raise SemanticWorkerFuzzError("missing corpus manifest: {}".format(manifest_path))
    return _load_json(manifest_path)


def _valid_seed_requests(corpus_root: Path, manifest: Dict[str, Any]) -> List[Tuple[Dict[str, Any], str]]:
    items = []
    for entry in manifest.get("valid", []):
        request = validate_semantic_request(_load_json(corpus_root / entry["path"]))
        items.append((request, entry["id"]))
    if not items:
        raise SemanticWorkerFuzzError("semantic fuzz corpus has no valid seeds")
    return items


def _invalid_seed_payloads(corpus_root: Path, manifest: Dict[str, Any]) -> List[Tuple[bytes, str]]:
    items = []
    for entry in manifest.get("invalid", []):
        items.append(((corpus_root / entry["path"]).read_bytes(), entry["id"]))
    if not items:
        raise SemanticWorkerFuzzError("semantic fuzz corpus has no invalid seeds")
    return items


def _handle_replay(worker_lib: Path, replay_input: Path) -> int:
    lib = load_semantic_worker(worker_lib)
    payload = replay_input.read_bytes()
    worker_result = _run_worker_raw(lib, payload)
    print("semantic worker replay")
    print("  worker: {}".format(worker_lib))
    print("  input: {}".format(replay_input))
    print("  outcome: {}".format(worker_result["outcome"]))
    if worker_result.get("error") is not None:
        print("  error: {}".format(worker_result["error"]))
    if worker_result.get("result") is not None:
        print(json.dumps(worker_result["result"], indent=2, sort_keys=True))
    return 0 if worker_result["outcome"] in ("success", "error") else 2


def main() -> int:
    parser = argparse.ArgumentParser(description="Deterministic semantic-worker fuzz runner")
    parser.add_argument("--worker-lib", type=Path, required=True, help="Path to semantic worker shared library")
    parser.add_argument("--corpus-root", type=Path, default=DEFAULT_CORPUS_ROOT, help="Semantic fuzz corpus root")
    parser.add_argument("--dictionary", type=Path, default=DEFAULT_DICTIONARY, help="Optional mutation dictionary")
    parser.add_argument("--seed", type=int, default=352, help="Deterministic RNG seed")
    parser.add_argument("--structured-iterations", type=int, default=128, help="Number of structured valid-request mutations")
    parser.add_argument("--raw-iterations", type=int, default=128, help="Number of raw-byte mutations")
    parser.add_argument("--max-payload-bytes", type=int, default=16384, help="Maximum mutated raw payload size")
    parser.add_argument("--json-out", type=Path, default=Path("build/semantic_worker_fuzz_report.json"), help="Machine-readable report output path")
    parser.add_argument("--markdown-out", type=Path, help="Optional markdown summary output path")
    parser.add_argument("--artifact-dir", type=Path, default=Path("build/semantic_worker_fuzz_artifacts"), help="Failure artifact root")
    parser.add_argument(
        "--max-failures",
        type=int,
        default=1,
        help="Maximum failures to collect before stopping (0 means unlimited)",
    )
    parser.add_argument("--replay-input", type=Path, help="Replay a single saved fuzz input")
    args = parser.parse_args()

    if args.replay_input is not None:
        try:
            return _handle_replay(args.worker_lib, args.replay_input)
        except Exception as exc:
            print("error: {}".format(exc), file=sys.stderr)
            return 2

    try:
        rng = random.Random(args.seed)
        reference_module = _load_reference_module()
        lib = load_semantic_worker(args.worker_lib)
        manifest = _load_corpus_manifest(args.corpus_root)
        valid_seeds = _valid_seed_requests(args.corpus_root, manifest)
        invalid_seeds = _invalid_seed_payloads(args.corpus_root, manifest)
        dictionary_tokens = _load_dictionary_tokens(args.dictionary)
    except Exception as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2

    if args.artifact_dir.exists():
        shutil.rmtree(args.artifact_dir)

    failures: List[Dict[str, Any]] = []
    failure_index = 0
    counts: Dict[str, int] = {
        "valid_baselines": 0,
        "valid_mutations": 0,
        "matched_reference_errors": 0,
        "invalid_baselines": 0,
        "invalid_mutations": 0,
    }

    def reached_failure_limit() -> bool:
        return args.max_failures > 0 and len(failures) >= args.max_failures

    def record_failure(
        lane: str,
        seed_id: str,
        description: str,
        error: str,
        input_bytes: bytes,
        reference_outcome: Optional[str],
        reference_result: Optional[Dict[str, Any]],
        reference_error: Optional[str],
        worker_result: Dict[str, Any],
    ) -> None:
        nonlocal failure_index
        summary = {
            "id": "{:04d}_{}".format(failure_index, lane),
            "lane": lane,
            "seed_id": seed_id,
            "description": description,
            "error": error,
            "worker_lib": str(args.worker_lib),
            "seed": args.seed,
        }
        artifact_dir = _write_failure_artifact(
            args.artifact_dir,
            lane,
            failure_index,
            args.worker_lib,
            summary,
            input_bytes,
            reference_result,
            reference_error,
            worker_result,
        )
        summary["artifact_dir"] = str(artifact_dir)

        minimization_info = None
        minimization_error = None
        try:
            request = json.loads(input_bytes.decode("utf-8"))
        except Exception:
            request = None

        try:
            if lane in ("valid_baseline", "structured_mutation") and isinstance(request, dict):
                base_observation = _structured_failure_observation(
                    reference_outcome or "error",
                    reference_result,
                    reference_error,
                    worker_result,
                )
                if base_observation is not None:
                    target_signature = base_observation["signature"]

                    def is_interesting(candidate_request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
                        reference_outcome, next_reference_result, next_reference_error = _run_reference(
                            reference_module, candidate_request
                        )
                        next_worker_result = _run_worker_raw(
                            lib, _canonical_request_bytes(candidate_request)
                        )
                        observation = _structured_failure_observation(
                            reference_outcome,
                            next_reference_result,
                            next_reference_error,
                            next_worker_result,
                        )
                        if observation is None or observation["signature"] != target_signature:
                            return None
                        return observation

                    minimization = minimize_structured_request(request, is_interesting)
                    minimization_info = _write_minimized_structured_artifact(
                        artifact_dir,
                        args.worker_lib,
                        summary,
                        input_bytes,
                        minimization,
                    )
            if minimization_info is None and lane in ("invalid_baseline", "raw_mutation"):
                base_observation = _raw_failure_observation(worker_result)
                if base_observation is not None:
                    target_signature = base_observation["signature"]

                    def is_interesting_raw(candidate_payload: bytes) -> Optional[Dict[str, Any]]:
                        next_worker_result = _run_worker_raw(lib, candidate_payload)
                        observation = _raw_failure_observation(next_worker_result)
                        if observation is None or observation["signature"] != target_signature:
                            return None
                        return observation

                    minimization = minimize_raw_payload(input_bytes, is_interesting_raw)
                    minimization_info = _write_minimized_raw_artifact(
                        artifact_dir,
                        args.worker_lib,
                        summary,
                        input_bytes,
                        minimization,
                    )
        except SemanticFuzzMinimizerError as exc:
            minimization_error = str(exc)
        except Exception as exc:
            minimization_error = str(exc)

        if minimization_info is not None:
            summary["minimization"] = minimization_info
        if minimization_error is not None:
            summary["minimization_error"] = minimization_error
        write_json(artifact_dir / "summary.json", summary)
        failures.append(summary)
        failure_index += 1

    for request, seed_id in valid_seeds:
        if reached_failure_limit():
            break
        request_bytes = _canonical_request_bytes(request)
        reference_outcome, reference_result, reference_error = _run_reference(reference_module, request)
        worker_result = _run_worker_raw(lib, request_bytes)
        if reference_outcome == "success" and worker_result["outcome"] == "success":
            errors = compare_semantic_results(reference_result, worker_result["result"])
            if errors:
                record_failure(
                    "valid_baseline",
                    seed_id,
                    "baseline corpus request",
                    "; ".join(errors),
                    request_bytes,
                    reference_outcome,
                    reference_result,
                    None,
                    worker_result,
                )
            else:
                counts["valid_baselines"] += 1
        elif reference_outcome == "error" and worker_result["outcome"] == "error":
            counts["matched_reference_errors"] += 1
        else:
            record_failure(
                "valid_baseline",
                seed_id,
                "baseline corpus request",
                "reference outcome {} vs worker outcome {}".format(reference_outcome, worker_result["outcome"]),
                request_bytes,
                reference_outcome,
                reference_result,
                reference_error,
                worker_result,
            )

    for iteration in range(args.structured_iterations):
        if reached_failure_limit():
            break
        seed_request, seed_id = rng.choice(valid_seeds)
        try:
            mutated_request, description = _mutate_valid_request(rng, seed_request)
        except Exception as exc:
            record_failure(
                "structured_mutation",
                seed_id,
                "mutation generation",
                str(exc),
                _canonical_request_bytes(seed_request),
                None,
                None,
                None,
                {"outcome": "mutation_error", "error": str(exc), "raw_output": None, "result": None},
            )
            continue
        request_bytes = _canonical_request_bytes(mutated_request)
        reference_outcome, reference_result, reference_error = _run_reference(reference_module, mutated_request)
        worker_result = _run_worker_raw(lib, request_bytes)
        if reference_outcome == "success" and worker_result["outcome"] == "success":
            errors = compare_semantic_results(reference_result, worker_result["result"])
            if errors:
                record_failure(
                    "structured_mutation",
                    seed_id,
                    description,
                    "; ".join(errors),
                    request_bytes,
                    reference_outcome,
                    reference_result,
                    None,
                    worker_result,
                )
            else:
                counts["valid_mutations"] += 1
        elif reference_outcome == "error" and worker_result["outcome"] == "error":
            counts["matched_reference_errors"] += 1
        else:
            record_failure(
                "structured_mutation",
                seed_id,
                description,
                "reference outcome {} vs worker outcome {}".format(reference_outcome, worker_result["outcome"]),
                request_bytes,
                reference_outcome,
                reference_result,
                reference_error,
                worker_result,
            )
        if reached_failure_limit():
            break

    for payload, seed_id in invalid_seeds:
        if reached_failure_limit():
            break
        worker_result = _run_worker_raw(lib, payload)
        if worker_result["outcome"] in ("error", "success"):
            counts["invalid_baselines"] += 1
        else:
            record_failure(
                "invalid_baseline",
                seed_id,
                "invalid corpus payload",
                worker_result["error"] or worker_result["outcome"],
                payload,
                None,
                None,
                None,
                worker_result,
            )
            if reached_failure_limit():
                break

    raw_pool = [payload for payload, _ in invalid_seeds] + [
        _canonical_request_bytes(request) for request, _ in valid_seeds
    ]
    for iteration in range(args.raw_iterations):
        if reached_failure_limit():
            break
        seed_payload = rng.choice(raw_pool)
        mutated_payload, description = _mutate_bytes(
            rng, seed_payload, dictionary_tokens, args.max_payload_bytes
        )
        worker_result = _run_worker_raw(lib, mutated_payload)
        if worker_result["outcome"] in ("error", "success"):
            counts["invalid_mutations"] += 1
        else:
            record_failure(
                "raw_mutation",
                "raw_{:04d}".format(iteration),
                description,
                worker_result["error"] or worker_result["outcome"],
                mutated_payload,
                None,
                None,
                None,
                worker_result,
            )
            if reached_failure_limit():
                break

    report = {
        "status": "passed" if not failures else "failed",
        "worker_lib": str(args.worker_lib),
        "seed": args.seed,
        "structured_iterations": args.structured_iterations,
        "raw_iterations": args.raw_iterations,
        "max_failures": args.max_failures,
        "valid_seed_count": len(valid_seeds),
        "invalid_seed_count": len(invalid_seeds),
        "counts": counts,
        "failure_count": len(failures),
        "failures": failures,
    }
    write_json(args.json_out, report)
    if args.markdown_out is not None:
        args.markdown_out.write_text(_render_markdown(report) + "\n", encoding="utf-8")

    if failures:
        print("FAIL: semantic worker fuzz failed", file=sys.stderr)
        print("  worker: {}".format(args.worker_lib), file=sys.stderr)
        for failure in failures[:10]:
            print(
                "  {}: {}".format(failure["id"], failure["error"]),
                file=sys.stderr,
            )
        print("  wrote report: {}".format(args.json_out), file=sys.stderr)
        if args.markdown_out is not None:
            print("  wrote markdown: {}".format(args.markdown_out), file=sys.stderr)
        return 2

    print("semantic worker fuzz OK")
    print("  worker: {}".format(args.worker_lib))
    print("  seed: {}".format(args.seed))
    print("  structured mutations: {}".format(counts["valid_mutations"]))
    print("  raw mutations: {}".format(counts["invalid_mutations"]))
    print("  wrote report: {}".format(args.json_out))
    if args.markdown_out is not None:
        print("  wrote markdown: {}".format(args.markdown_out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
