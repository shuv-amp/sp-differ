#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Deterministic fuzz runner for semantic command adapters."""

import argparse
import json
import random
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from bip352_reference import load_reference_module
from bip352_semantics import derive_receive_semantics, derive_sender_semantics
from bip352_vectors import write_json
from semantic_adapter import case_from_semantic_request, validate_semantic_request
from semantic_contract import compare_semantic_results, validate_semantic_result
from run_semantic_worker_fuzz import _mutate_valid_request

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS_ROOT = ROOT / "fuzz" / "corpus" / "semantic_worker"
DEFAULT_REFERENCE = ROOT / "tests" / "vectors" / "bip352" / "official" / "reference" / "reference.py"


class SemanticAdapterFuzzError(Exception):
    pass


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_reference_module():
    return load_reference_module(DEFAULT_REFERENCE, DEFAULT_REFERENCE.parent)


def _load_corpus_manifest(corpus_root: Path) -> Dict[str, Any]:
    manifest_path = corpus_root / "manifest.json"
    if not manifest_path.exists():
        raise SemanticAdapterFuzzError("missing corpus manifest: {}".format(manifest_path))
    return _load_json(manifest_path)


def _valid_seed_requests(corpus_root: Path, manifest: Dict[str, Any]) -> List[Tuple[Dict[str, Any], str]]:
    items = []
    for entry in manifest.get("valid", []):
        request = validate_semantic_request(_load_json(corpus_root / entry["path"]))
        items.append((request, entry["id"]))
    if not items:
        raise SemanticAdapterFuzzError("semantic fuzz corpus has no valid seeds")
    return items


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


def _run_adapter(command: List[str], request: Dict[str, Any], timeout_seconds: float) -> Dict[str, Any]:
    proc = subprocess.run(
        command,
        input=json.dumps(request, sort_keys=True).encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout_seconds,
    )
    if proc.returncode != 0:
        return {
            "outcome": "error",
            "error": "adapter exited with status {}: {}".format(
                proc.returncode, proc.stderr.decode("utf-8", errors="replace").strip()
            ),
            "result": None,
        }
    try:
        decoded = json.loads(proc.stdout.decode("utf-8"))
    except Exception as exc:
        return {
            "outcome": "invalid_json",
            "error": str(exc),
            "result": None,
        }
    try:
        result = validate_semantic_result(decoded)
    except Exception as exc:
        return {
            "outcome": "invalid_contract",
            "error": str(exc),
            "result": None,
        }
    return {"outcome": "success", "error": None, "result": result}


def _evaluate_request(
    reference_module,
    adapter_cmd: List[str],
    request: Dict[str, Any],
    timeout_seconds: float,
) -> Dict[str, Any]:
    reference_outcome, reference_result, reference_error = _run_reference(reference_module, request)
    adapter_result = _run_adapter(adapter_cmd, request, timeout_seconds)

    if reference_outcome == "success" and adapter_result["outcome"] == "success":
        errors = compare_semantic_results(reference_result, adapter_result["result"])
    elif reference_outcome == "error" and adapter_result["outcome"] == "error":
        errors = []
    else:
        errors = [
            "reference outcome {} vs adapter outcome {}".format(
                reference_outcome, adapter_result["outcome"]
            )
        ]

    return {
        "reference_outcome": reference_outcome,
        "reference_result": reference_result,
        "reference_error": reference_error,
        "adapter_result": adapter_result,
        "errors": errors,
    }


def _write_failure_artifact(
    artifact_root: Path,
    index: int,
    seed_id: str,
    description: str,
    adapter_name: str,
    adapter_cmd: List[str],
    timeout_seconds: float,
    request: Dict[str, Any],
    reference_result: Optional[Dict[str, Any]],
    reference_error: Optional[str],
    adapter_result: Dict[str, Any],
    errors: List[str],
) -> Path:
    failure_dir = artifact_root / "{:04d}".format(index)
    failure_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "id": "{:04d}".format(index),
        "seed_id": seed_id,
        "description": description,
        "adapter_name": adapter_name,
        "adapter_cmd": adapter_cmd,
        "errors": errors,
        "request_path": str(failure_dir / "request.json"),
    }

    request_path = failure_dir / "request.json"
    replay_report_path = failure_dir / "replay_report.json"
    replay_path = failure_dir / "replay.sh"

    write_json(request_path, request)

    repro_cmd = [
        "python3",
        "scripts/run_semantic_adapter_fuzz.py",
        "--adapter-name",
        adapter_name,
        "--adapter-cmd",
        shlex.join(adapter_cmd),
        "--request-path",
        str(request_path),
        "--timeout-seconds",
        str(timeout_seconds),
        "--json-out",
        str(replay_report_path),
    ]
    summary["repro_cmd"] = shlex.join(repro_cmd)
    summary["replay_cmd"] = summary["repro_cmd"]

    write_json(failure_dir / "summary.json", summary)
    if reference_result is not None:
        write_json(failure_dir / "expected.json", reference_result)
    if reference_error is not None:
        (failure_dir / "reference_error.txt").write_text(reference_error + "\n", encoding="utf-8")
    if adapter_result.get("result") is not None:
        write_json(failure_dir / "actual.json", adapter_result["result"])
    if adapter_result.get("error") is not None:
        (failure_dir / "adapter_error.txt").write_text(adapter_result["error"] + "\n", encoding="utf-8")
    replay_path.write_text(
        "#!/bin/sh\nset -eu\n{}\n".format(summary["repro_cmd"]),
        encoding="utf-8",
    )
    replay_path.chmod(0o755)

    return failure_dir


def _render_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Semantic Adapter Fuzz Report",
        "",
        "- adapter: `{}`".format(report["adapter_name"]),
        "- mode: `{}`".format(report.get("mode", "fuzz")),
        "- seed: `{}`".format(report.get("seed", "n/a")),
        "- iterations: `{}`".format(report.get("iterations", "n/a")),
        "- max_failures: `{}`".format(report.get("max_failures", "n/a")),
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
        lines.append("- seed: `{}`".format(failure.get("seed_id", "n/a")))
        lines.append("- description: `{}`".format(failure.get("description", "replay_request")))
        lines.append("- errors: `{}`".format("; ".join(failure["errors"])))
        if failure.get("artifact_dir"):
            lines.append("- artifact_dir: `{}`".format(failure["artifact_dir"]))
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Deterministic semantic-adapter fuzz runner")
    parser.add_argument("--adapter-name", required=True, help="Adapter name for reports")
    parser.add_argument("--adapter-cmd", required=True, help="Shell command to execute adapter")
    parser.add_argument(
        "--request-path",
        type=Path,
        help="Optional saved semantic adapter request to replay exactly once instead of fuzzing",
    )
    parser.add_argument("--corpus-root", type=Path, default=DEFAULT_CORPUS_ROOT, help="Semantic fuzz corpus root")
    parser.add_argument("--seed", type=int, default=352, help="Deterministic RNG seed")
    parser.add_argument("--iterations", type=int, default=64, help="Structured mutation iterations")
    parser.add_argument("--max-failures", type=int, default=1, help="Maximum failures to collect (0 means unlimited)")
    parser.add_argument("--timeout-seconds", type=float, default=30.0, help="Per-case adapter timeout")
    parser.add_argument("--json-out", type=Path, default=Path("build/semantic_adapter_fuzz_report.json"), help="Machine-readable report output path")
    parser.add_argument("--markdown-out", type=Path, help="Optional markdown summary output path")
    parser.add_argument("--artifact-dir", type=Path, default=Path("build/semantic_adapter_fuzz_artifacts"), help="Failure artifact root")
    args = parser.parse_args()

    try:
        reference_module = _load_reference_module()
        adapter_cmd = shlex.split(args.adapter_cmd)
        if not adapter_cmd:
            raise SemanticAdapterFuzzError("empty adapter command")
        if args.request_path is None:
            rng = random.Random(args.seed)
            manifest = _load_corpus_manifest(args.corpus_root)
            valid_seeds = _valid_seed_requests(args.corpus_root, manifest)
        else:
            valid_seeds = []
    except Exception as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2

    if args.request_path is not None:
        try:
            request = validate_semantic_request(_load_json(args.request_path))
        except Exception as exc:
            print("error: invalid replay request: {}".format(exc), file=sys.stderr)
            return 2

        evaluation = _evaluate_request(reference_module, adapter_cmd, request, args.timeout_seconds)
        report = {
            "status": "passed" if not evaluation["errors"] else "failed",
            "mode": "replay_request",
            "adapter_name": args.adapter_name,
            "adapter_cmd": adapter_cmd,
            "request_path": str(args.request_path),
            "failure_count": 0 if not evaluation["errors"] else 1,
            "failures": [],
        }
        if evaluation["errors"]:
            report["failures"].append(
                {
                    "id": args.request_path.stem,
                    "errors": evaluation["errors"],
                    "reference_outcome": evaluation["reference_outcome"],
                    "adapter_outcome": evaluation["adapter_result"]["outcome"],
                }
            )
        write_json(args.json_out, report)
        if args.markdown_out is not None:
            args.markdown_out.write_text(_render_markdown(report) + "\n", encoding="utf-8")
        if evaluation["errors"]:
            print("FAIL: semantic adapter replay failed", file=sys.stderr)
            print("  adapter: {}".format(args.adapter_name), file=sys.stderr)
            for failure in report["failures"]:
                print("  {}: {}".format(failure["id"], "; ".join(failure["errors"])), file=sys.stderr)
            print("  wrote report: {}".format(args.json_out), file=sys.stderr)
            if args.markdown_out is not None:
                print("  wrote markdown: {}".format(args.markdown_out), file=sys.stderr)
            return 2

        print("semantic adapter replay OK")
        print("  adapter: {}".format(args.adapter_name))
        print("  request_path: {}".format(args.request_path))
        print("  wrote report: {}".format(args.json_out))
        if args.markdown_out is not None:
            print("  wrote markdown: {}".format(args.markdown_out))
        return 0

    if args.artifact_dir.exists():
        shutil.rmtree(args.artifact_dir)

    failures: List[Dict[str, Any]] = []
    counts = {
        "baselines_ok": 0,
        "mutations_ok": 0,
        "matched_reference_errors": 0,
    }

    def reached_limit() -> bool:
        return args.max_failures > 0 and len(failures) >= args.max_failures

    def record_failure(
        seed_id: str,
        description: str,
        request: Dict[str, Any],
        reference_result: Optional[Dict[str, Any]],
        reference_error: Optional[str],
        adapter_result: Dict[str, Any],
        errors: List[str],
    ) -> None:
        failure_id = "{:04d}".format(len(failures))
        artifact_dir = _write_failure_artifact(
            args.artifact_dir,
            len(failures),
            seed_id,
            description,
            args.adapter_name,
            adapter_cmd,
            args.timeout_seconds,
            request,
            reference_result,
            reference_error,
            adapter_result,
            errors,
        )
        failures.append(
            {
                "id": failure_id,
                "seed_id": seed_id,
                "description": description,
                "errors": errors,
                "artifact_dir": str(artifact_dir),
            }
        )

    for request, seed_id in valid_seeds:
        if reached_limit():
            break
        evaluation = _evaluate_request(reference_module, adapter_cmd, request, args.timeout_seconds)
        reference_outcome = evaluation["reference_outcome"]
        reference_result = evaluation["reference_result"]
        reference_error = evaluation["reference_error"]
        adapter_result = evaluation["adapter_result"]
        errors = evaluation["errors"]

        if reference_outcome == "success" and adapter_result["outcome"] == "success":
            if errors:
                record_failure(
                    seed_id,
                    "baseline",
                    request,
                    reference_result,
                    None,
                    adapter_result,
                    errors,
                )
            else:
                counts["baselines_ok"] += 1
        elif reference_outcome == "error" and adapter_result["outcome"] == "error":
            counts["matched_reference_errors"] += 1
        else:
            record_failure(
                seed_id,
                "baseline",
                request,
                reference_result,
                reference_error,
                adapter_result,
                [
                    "reference outcome {} vs adapter outcome {}".format(
                        reference_outcome, adapter_result["outcome"]
                    )
                ],
            )

    for iteration in range(args.iterations):
        if reached_limit():
            break
        seed_request, seed_id = rng.choice(valid_seeds)
        try:
            mutated_request, description = _mutate_valid_request(rng, seed_request)
        except Exception as exc:
            record_failure(
                seed_id,
                "mutation generation",
                seed_request,
                None,
                None,
                {"outcome": "mutation_error", "error": str(exc), "result": None},
                [str(exc)],
            )
            continue

        evaluation = _evaluate_request(reference_module, adapter_cmd, mutated_request, args.timeout_seconds)
        reference_outcome = evaluation["reference_outcome"]
        reference_result = evaluation["reference_result"]
        reference_error = evaluation["reference_error"]
        adapter_result = evaluation["adapter_result"]
        errors = evaluation["errors"]

        if reference_outcome == "success" and adapter_result["outcome"] == "success":
            if errors:
                record_failure(
                    seed_id,
                    description,
                    mutated_request,
                    reference_result,
                    None,
                    adapter_result,
                    errors,
                )
            else:
                counts["mutations_ok"] += 1
        elif reference_outcome == "error" and adapter_result["outcome"] == "error":
            counts["matched_reference_errors"] += 1
        else:
            record_failure(
                seed_id,
                description,
                mutated_request,
                reference_result,
                reference_error,
                adapter_result,
                [
                    "reference outcome {} vs adapter outcome {}".format(
                        reference_outcome, adapter_result["outcome"]
                    )
                ],
            )

    report = {
        "status": "passed" if not failures else "failed",
        "adapter_name": args.adapter_name,
        "adapter_cmd": adapter_cmd,
        "seed": args.seed,
        "iterations": args.iterations,
        "max_failures": args.max_failures,
        "valid_seed_count": len(valid_seeds),
        "counts": counts,
        "failure_count": len(failures),
        "failures": failures,
    }
    write_json(args.json_out, report)
    if args.markdown_out is not None:
        args.markdown_out.write_text(_render_markdown(report) + "\n", encoding="utf-8")

    if failures:
        print("FAIL: semantic adapter fuzz failed", file=sys.stderr)
        print("  adapter: {}".format(args.adapter_name), file=sys.stderr)
        for failure in failures[:10]:
            print("  {}: {}".format(failure["id"], "; ".join(failure["errors"])), file=sys.stderr)
        print("  wrote report: {}".format(args.json_out), file=sys.stderr)
        if args.markdown_out is not None:
            print("  wrote markdown: {}".format(args.markdown_out), file=sys.stderr)
        return 2

    print("semantic adapter fuzz OK")
    print("  adapter: {}".format(args.adapter_name))
    print("  seed: {}".format(args.seed))
    print("  iterations: {}".format(args.iterations))
    print("  wrote report: {}".format(args.json_out))
    if args.markdown_out is not None:
        print("  wrote markdown: {}".format(args.markdown_out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
