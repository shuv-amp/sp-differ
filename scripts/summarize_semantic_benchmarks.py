#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Summarize comparable semantic benchmark reports."""

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from bip352_vectors import write_json


def _format_rate(value: Any) -> str:
    if value is None:
        return "n/a"
    return "{:.2f} cases/s".format(value)


def _format_millis(value: Any) -> str:
    if value is None:
        return "n/a"
    return "{:.3f} ms".format(value * 1000.0)


def _render_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Semantic Benchmark Summary",
        "",
        "- comparable: `{}`".format("yes" if report["comparable"] else "no"),
        "- reports: `{}`".format(len(report["benchmarks"])),
        "",
        "Command-adapter results include process startup, and worker-lib results include the semantic worker bridge. Treat this as a harness benchmark, not a universal library-speed claim.",
        "",
        "| Adapter | Status | Adapter Throughput | End-to-End Throughput | Median Adapter | P95 Adapter |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for item in report["benchmarks"]:
        lines.append(
            "| `{}` | `{}` | {} | {} | {} | {} |".format(
                item["adapter_name"],
                item["status"],
                _format_rate(item["adapter_cases_per_second"]),
                _format_rate(item["end_to_end_cases_per_second"]),
                _format_millis(item["adapter_median_seconds"]),
                _format_millis(item["adapter_p95_seconds"]),
            )
        )
    lines.append("")
    mismatches = report.get("signature_mismatches", [])
    if mismatches:
        lines.extend(["## Signature Mismatches", ""])
        for mismatch in mismatches:
            lines.append("- `{}`: {}".format(mismatch["path"], mismatch["reason"]))
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize semantic benchmark reports")
    parser.add_argument("reports", nargs="+", type=Path, help="Benchmark JSON reports to summarize")
    parser.add_argument("--json-out", type=Path, default=Path("build/semantic_benchmark_summary.json"))
    parser.add_argument("--markdown-out", type=Path, help="Optional markdown summary path")
    args = parser.parse_args()

    loaded: List[Dict[str, Any]] = []
    signature_mismatches: List[Dict[str, str]] = []
    baseline_signature = None
    for path in args.reports:
        payload = json.loads(path.read_text(encoding="utf-8"))
        signature = payload.get("comparison_signature")
        if baseline_signature is None:
            baseline_signature = signature
        elif signature != baseline_signature:
            signature_mismatches.append(
                {
                    "path": str(path),
                    "reason": "comparison_signature differs from the first report",
                }
            )
        loaded.append(
            {
                "path": str(path),
                "adapter_name": payload["adapter_name"],
                "status": payload["status"],
                "selected_case_count": payload["selected_case_count"],
                "measured_iterations": payload["measured_iterations"],
                "adapter_cases_per_second": payload["adapter_latency_seconds"]["cases_per_second"],
                "end_to_end_cases_per_second": payload["end_to_end_latency_seconds"]["cases_per_second"],
                "adapter_median_seconds": payload["adapter_latency_seconds"]["median_seconds"],
                "adapter_p95_seconds": payload["adapter_latency_seconds"]["p95_seconds"],
                "comparison_signature": signature,
            }
        )

    loaded.sort(
        key=lambda item: (
            item["status"] != "passed",
            -(item["adapter_cases_per_second"] or 0.0),
            item["adapter_name"],
        )
    )

    report = {
        "comparable": not signature_mismatches,
        "comparison_signature": baseline_signature,
        "benchmarks": loaded,
        "signature_mismatches": signature_mismatches,
    }
    write_json(args.json_out, report)
    if args.markdown_out is not None:
        args.markdown_out.write_text(_render_markdown(report) + "\n", encoding="utf-8")
    print("semantic benchmark summary OK")
    print("  reports: {}".format(len(loaded)))
    print("  comparable: {}".format("yes" if report["comparable"] else "no"))
    print("  wrote report: {}".format(args.json_out))
    if args.markdown_out is not None:
        print("  wrote markdown: {}".format(args.markdown_out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
