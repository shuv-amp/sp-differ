#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Benchmark a semantic adapter or worker over the derived v2 corpus."""

import argparse
import hashlib
import json
import math
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from bip352_reference import verify_reference_manifest
from bip352_vectors import write_json
from semantic_adapter import build_semantic_request
from semantic_case_runner import build_adapter_command, read_case_v2, run_adapter
from semantic_contract import compare_semantic_results, validate_semantic_result


def _percentile(values: List[float], pct: float) -> Optional[float]:
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    ordered = sorted(values)
    index = int(math.ceil(pct * len(ordered))) - 1
    return ordered[max(0, min(index, len(ordered) - 1))]


def _stats(values: List[float]) -> Dict[str, Any]:
    if not values:
        return {
            "count": 0,
            "total_seconds": 0.0,
            "cases_per_second": None,
            "min_seconds": None,
            "median_seconds": None,
            "p95_seconds": None,
            "max_seconds": None,
        }
    total = sum(values)
    return {
        "count": len(values),
        "total_seconds": total,
        "cases_per_second": None if total <= 0.0 else len(values) / total,
        "min_seconds": min(values),
        "median_seconds": statistics.median(values),
        "p95_seconds": _percentile(values, 0.95),
        "max_seconds": max(values),
    }


def _format_millis(value: Optional[float]) -> str:
    if value is None:
        return "n/a"
    return "{:.3f} ms".format(value * 1000.0)


def _format_rate(value: Optional[float]) -> str:
    if value is None:
        return "n/a"
    return "{:.2f} cases/s".format(value)


def _render_markdown_report(report: Dict[str, Any]) -> str:
    lines = [
        "# Semantic Adapter Benchmark",
        "",
        "- adapter: `{}`".format(report["adapter_name"]),
        "- status: `{}`".format(report["status"]),
        "- upstream_commit: `{}`".format(report["upstream_commit"]),
        "- snapshot_sha256: `{}`".format(report["snapshot_sha256"]),
        "- selected_cases: `{}`".format(report["selected_case_count"]),
        "- warmup_iterations: `{}`".format(report["warmup_iterations"]),
        "- measured_iterations: `{}`".format(report["measured_iterations"]),
        "- measured_case_runs: `{}`".format(report["measured_case_runs"]),
        "- adapter_throughput: `{}`".format(
            _format_rate(report["adapter_latency_seconds"]["cases_per_second"])
        ),
        "- end_to_end_throughput: `{}`".format(
            _format_rate(report["end_to_end_latency_seconds"]["cases_per_second"])
        ),
        "- median_adapter_latency: `{}`".format(
            _format_millis(report["adapter_latency_seconds"]["median_seconds"])
        ),
        "- p95_adapter_latency: `{}`".format(
            _format_millis(report["adapter_latency_seconds"]["p95_seconds"])
        ),
        "- median_end_to_end_latency: `{}`".format(
            _format_millis(report["end_to_end_latency_seconds"]["median_seconds"])
        ),
        "- p95_end_to_end_latency: `{}`".format(
            _format_millis(report["end_to_end_latency_seconds"]["p95_seconds"])
        ),
        "",
        "These measurements exclude one-time corpus parsing/request construction and compare only like-for-like runs that share the same selection signature.",
        "",
    ]

    lines.extend(["## By Kind", ""])
    for kind, stats in report["by_kind"].items():
        lines.append("### `{}`".format(kind))
        lines.append("")
        lines.append("- case_runs: `{}`".format(stats["adapter_latency_seconds"]["count"]))
        lines.append(
            "- adapter_throughput: `{}`".format(
                _format_rate(stats["adapter_latency_seconds"]["cases_per_second"])
            )
        )
        lines.append(
            "- median_adapter_latency: `{}`".format(
                _format_millis(stats["adapter_latency_seconds"]["median_seconds"])
            )
        )
        lines.append(
            "- p95_adapter_latency: `{}`".format(
                _format_millis(stats["adapter_latency_seconds"]["p95_seconds"])
            )
        )
        lines.append("")

    slowest = report.get("slowest_cases", [])
    if slowest:
        lines.extend(["## Slowest Cases", ""])
        for item in slowest:
            lines.append(
                "- `{}` (`{}`): median adapter `{}`, p95 adapter `{}`".format(
                    item["id"],
                    item["kind"],
                    _format_millis(item["adapter_latency_seconds"]["median_seconds"]),
                    _format_millis(item["adapter_latency_seconds"]["p95_seconds"]),
                )
            )
        lines.append("")

    failures = report.get("failures", [])
    if failures:
        lines.extend(["## Failures", ""])
        for failure in failures:
            lines.append("### `{}`".format(failure["id"]))
            lines.append("")
            lines.append("- iteration: `{}`".format(failure["iteration"]))
            lines.append("- error: `{}`".format(failure["error"]))
            lines.append("")

    return "\n".join(lines)


def _selection_signature(
    snapshot_sha256: str,
    manifest_path: Path,
    prepared_cases: List[Dict[str, Any]],
    warmup_iterations: int,
    measured_iterations: int,
    timeout_seconds: float,
) -> Dict[str, Any]:
    case_ids = [item["id"] for item in prepared_cases]
    digest = hashlib.sha256("\n".join(case_ids).encode("utf-8")).hexdigest()
    return {
        "snapshot_sha256": snapshot_sha256,
        "derived_manifest": str(manifest_path),
        "selected_case_count": len(case_ids),
        "selected_case_ids_sha256": digest,
        "warmup_iterations": warmup_iterations,
        "measured_iterations": measured_iterations,
        "timeout_seconds": timeout_seconds,
    }


def _prepare_cases(args: argparse.Namespace) -> Dict[str, Any]:
    official_manifest, verification, _ = verify_reference_manifest(
        args.official_manifest, args.official_vectors
    )
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    cases = manifest.get("cases", [])
    if not isinstance(cases, list):
        raise RuntimeError("manifest cases must be a list")
    if args.kind is not None:
        cases = [item for item in cases if item.get("kind") == args.kind]
    if args.case_id:
        selected = set(args.case_id)
        cases = [item for item in cases if item.get("id") in selected]
        missing = sorted(selected.difference(item.get("id") for item in cases))
        if missing:
            raise RuntimeError("unknown case id(s): {}".format(", ".join(missing)))
    if args.max_cases is not None:
        if args.max_cases <= 0:
            raise RuntimeError("max_cases must be positive")
        cases = cases[: args.max_cases]
    if not cases:
        raise RuntimeError("manifest selection is empty")

    prepared_cases: List[Dict[str, Any]] = []
    for item in cases:
        case_path = args.manifest.parent / item["path"]
        expectation_path = args.manifest.parent / item["expectation_path"]
        expected = validate_semantic_result(json.loads(expectation_path.read_text(encoding="utf-8")))
        case = read_case_v2(case_path)
        expectation_hints = None
        if item["kind"] == "receive":
            expectation_hints = {
                "detailed_outputs_required": bool(expected.get("detailed_outputs_available", True))
            }
        request = build_semantic_request(
            item["kind"], case, expected["source"], expectation_hints=expectation_hints
        )
        prepared_cases.append(
            {
                "id": item["id"],
                "kind": item["kind"],
                "request": request,
                "expected": expected,
            }
        )

    adapter_cmd, repro_target_args = build_adapter_command(args.adapter_cmd, args.worker_lib)
    return {
        "official_manifest": official_manifest,
        "verification": verification,
        "prepared_cases": prepared_cases,
        "adapter_cmd": adapter_cmd,
        "repro_target_args": repro_target_args,
    }


def _execute_once(
    adapter_cmd: List[str],
    prepared_case: Dict[str, Any],
    timeout_seconds: float,
) -> Dict[str, Any]:
    adapter_start = time.perf_counter()
    raw = run_adapter(adapter_cmd, prepared_case["request"], timeout_seconds)
    adapter_elapsed = time.perf_counter() - adapter_start

    contract_start = time.perf_counter()
    actual = validate_semantic_result(raw)
    errors = compare_semantic_results(prepared_case["expected"], actual)
    contract_elapsed = time.perf_counter() - contract_start
    return {
        "adapter_elapsed_seconds": adapter_elapsed,
        "contract_elapsed_seconds": contract_elapsed,
        "total_elapsed_seconds": adapter_elapsed + contract_elapsed,
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark a semantic adapter against derived v2 cases")
    parser.add_argument("--adapter-name", required=True, help="Human-readable adapter name")
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--adapter-cmd", help="Shell-style command used to execute the adapter")
    target_group.add_argument("--worker-lib", type=Path, help="Path to semantic worker shared library")
    parser.add_argument(
        "--official-manifest",
        type=Path,
        default=Path("tests/vectors/bip352/official/manifest.json"),
        help="Path to the vendored official manifest",
    )
    parser.add_argument(
        "--official-vectors",
        type=Path,
        default=Path("tests/vectors/bip352/official/send_and_receive_test_vectors.json"),
        help="Path to the vendored official vector snapshot",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("tests/vectors/bip352/derived/v2/manifest.json"),
        help="Path to the derived v2 manifest",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=Path("build/semantic_adapter_benchmark.json"),
        help="Where to write the machine-readable benchmark report",
    )
    parser.add_argument("--markdown-out", type=Path, help="Optional markdown summary path")
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=30.0,
        help="Per-case adapter execution timeout in seconds",
    )
    parser.add_argument(
        "--warmup-iterations",
        type=int,
        default=1,
        help="Warmup passes to execute before recording timings",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=3,
        help="Measured passes over the selected corpus",
    )
    parser.add_argument(
        "--kind",
        choices=("send", "receive"),
        help="Optional case-kind filter",
    )
    parser.add_argument(
        "--case-id",
        action="append",
        help="Optional case id filter; may be passed more than once",
    )
    parser.add_argument(
        "--max-cases",
        type=int,
        help="Optional cap on selected cases after filters are applied",
    )
    parser.add_argument(
        "--slowest-limit",
        type=int,
        default=10,
        help="How many slowest cases to include in the markdown and JSON summary",
    )
    args = parser.parse_args()

    if args.warmup_iterations < 0:
        print("error: warmup_iterations must be non-negative", file=sys.stderr)
        return 2
    if args.iterations <= 0:
        print("error: iterations must be positive", file=sys.stderr)
        return 2

    try:
        prepared = _prepare_cases(args)
    except Exception as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2

    adapter_cmd = prepared["adapter_cmd"]
    prepared_cases = prepared["prepared_cases"]
    verification = prepared["verification"]
    official_manifest = prepared["official_manifest"]

    adapter_timings: List[float] = []
    contract_timings: List[float] = []
    total_timings: List[float] = []
    by_kind_timings: Dict[str, Dict[str, List[float]]] = {
        "send": {"adapter": [], "contract": [], "total": []},
        "receive": {"adapter": [], "contract": [], "total": []},
    }
    per_case_timings: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"kind": None, "adapter": [], "contract": [], "total": []}
    )
    iteration_summaries: List[Dict[str, float]] = []
    failures: List[Dict[str, Any]] = []

    for _ in range(args.warmup_iterations):
        for prepared_case in prepared_cases:
            try:
                result = _execute_once(adapter_cmd, prepared_case, args.timeout_seconds)
            except Exception as exc:
                failures.append(
                    {
                        "id": prepared_case["id"],
                        "kind": prepared_case["kind"],
                        "iteration": "warmup",
                        "error": str(exc),
                    }
                )
                break
            if result["errors"]:
                failures.append(
                    {
                        "id": prepared_case["id"],
                        "kind": prepared_case["kind"],
                        "iteration": "warmup",
                        "error": "; ".join(result["errors"]),
                    }
                )
                break
        if failures:
            break

    if not failures:
        for iteration in range(args.iterations):
            iteration_adapter_total = 0.0
            iteration_contract_total = 0.0
            iteration_total = 0.0
            for prepared_case in prepared_cases:
                try:
                    result = _execute_once(adapter_cmd, prepared_case, args.timeout_seconds)
                except Exception as exc:
                    failures.append(
                        {
                            "id": prepared_case["id"],
                            "kind": prepared_case["kind"],
                            "iteration": iteration + 1,
                            "error": str(exc),
                        }
                    )
                    break
                if result["errors"]:
                    failures.append(
                        {
                            "id": prepared_case["id"],
                            "kind": prepared_case["kind"],
                            "iteration": iteration + 1,
                            "error": "; ".join(result["errors"]),
                        }
                    )
                    break

                adapter_elapsed = result["adapter_elapsed_seconds"]
                contract_elapsed = result["contract_elapsed_seconds"]
                total_elapsed = result["total_elapsed_seconds"]

                adapter_timings.append(adapter_elapsed)
                contract_timings.append(contract_elapsed)
                total_timings.append(total_elapsed)
                by_kind_timings[prepared_case["kind"]]["adapter"].append(adapter_elapsed)
                by_kind_timings[prepared_case["kind"]]["contract"].append(contract_elapsed)
                by_kind_timings[prepared_case["kind"]]["total"].append(total_elapsed)

                case_stats = per_case_timings[prepared_case["id"]]
                case_stats["kind"] = prepared_case["kind"]
                case_stats["adapter"].append(adapter_elapsed)
                case_stats["contract"].append(contract_elapsed)
                case_stats["total"].append(total_elapsed)

                iteration_adapter_total += adapter_elapsed
                iteration_contract_total += contract_elapsed
                iteration_total += total_elapsed
            if failures:
                break
            iteration_summaries.append(
                {
                    "iteration": iteration + 1,
                    "adapter_seconds": iteration_adapter_total,
                    "contract_seconds": iteration_contract_total,
                    "end_to_end_seconds": iteration_total,
                }
            )

    slowest_cases = []
    for case_id, timings in per_case_timings.items():
        slowest_cases.append(
            {
                "id": case_id,
                "kind": timings["kind"],
                "adapter_latency_seconds": _stats(timings["adapter"]),
                "contract_latency_seconds": _stats(timings["contract"]),
                "end_to_end_latency_seconds": _stats(timings["total"]),
            }
        )
    slowest_cases.sort(
        key=lambda item: item["adapter_latency_seconds"]["median_seconds"] or 0.0,
        reverse=True,
    )
    slowest_cases = slowest_cases[: max(0, args.slowest_limit)]

    report = {
        "status": "passed" if not failures else "failed",
        "adapter_name": args.adapter_name,
        "adapter_cmd": adapter_cmd,
        "repro_target_args": prepared["repro_target_args"],
        "upstream_commit": official_manifest.get("upstream_commit"),
        "snapshot_sha256": verification["snapshot_sha256"],
        "derived_manifest": str(args.manifest),
        "selected_case_count": len(prepared_cases),
        "selected_case_ids": [item["id"] for item in prepared_cases],
        "selection": {
            "kind": args.kind,
            "case_ids": args.case_id or [],
            "max_cases": args.max_cases,
        },
        "warmup_iterations": args.warmup_iterations,
        "measured_iterations": args.iterations,
        "measured_case_runs": len(adapter_timings),
        "timeout_seconds": args.timeout_seconds,
        "comparison_signature": _selection_signature(
            verification["snapshot_sha256"],
            args.manifest,
            prepared_cases,
            args.warmup_iterations,
            args.iterations,
            args.timeout_seconds,
        ),
        "adapter_latency_seconds": _stats(adapter_timings),
        "contract_latency_seconds": _stats(contract_timings),
        "end_to_end_latency_seconds": _stats(total_timings),
        "by_kind": {
            kind: {
                "adapter_latency_seconds": _stats(values["adapter"]),
                "contract_latency_seconds": _stats(values["contract"]),
                "end_to_end_latency_seconds": _stats(values["total"]),
            }
            for kind, values in by_kind_timings.items()
            if values["adapter"]
        },
        "iteration_summaries": iteration_summaries,
        "slowest_cases": slowest_cases,
        "failures": failures,
    }
    write_json(args.json_out, report)
    if args.markdown_out is not None:
        args.markdown_out.write_text(_render_markdown_report(report) + "\n", encoding="utf-8")

    if failures:
        print("FAIL: semantic adapter benchmark failed", file=sys.stderr)
        print("  adapter: {}".format(args.adapter_name), file=sys.stderr)
        for failure in failures[:10]:
            print(
                "  {} (iteration {}): {}".format(
                    failure["id"], failure["iteration"], failure["error"]
                ),
                file=sys.stderr,
            )
        print("  wrote report: {}".format(args.json_out), file=sys.stderr)
        if args.markdown_out is not None:
            print("  wrote markdown: {}".format(args.markdown_out), file=sys.stderr)
        return 2

    print("semantic adapter benchmark OK")
    print("  adapter: {}".format(args.adapter_name))
    print("  selected cases: {}".format(report["selected_case_count"]))
    print("  measured iterations: {}".format(report["measured_iterations"]))
    print(
        "  adapter throughput: {}".format(
            _format_rate(report["adapter_latency_seconds"]["cases_per_second"])
        )
    )
    print("  wrote report: {}".format(args.json_out))
    if args.markdown_out is not None:
        print("  wrote markdown: {}".format(args.markdown_out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
