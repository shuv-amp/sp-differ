#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Smoke-test the semantic benchmark tooling against the reference adapter."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "scripts" / "benchmark_semantic_adapter.py"
SUMMARY = ROOT / "scripts" / "summarize_semantic_benchmarks.py"


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="sp_differ_bench_smoke_") as tmp_dir:
        tmp_root = Path(tmp_dir)
        report_path = tmp_root / "reference_benchmark.json"
        markdown_path = tmp_root / "reference_benchmark.md"
        summary_path = tmp_root / "benchmark_summary.json"
        summary_markdown_path = tmp_root / "benchmark_summary.md"

        subprocess.run(
            [
                sys.executable,
                str(BENCH),
                "--adapter-name",
                "reference",
                "--adapter-cmd",
                "{} {}".format(sys.executable, ROOT / "adapters" / "reference" / "semantic_adapter.py"),
                "--kind",
                "send",
                "--max-cases",
                "2",
                "--warmup-iterations",
                "0",
                "--iterations",
                "1",
                "--json-out",
                str(report_path),
                "--markdown-out",
                str(markdown_path),
            ],
            cwd=ROOT,
            check=True,
        )

        report = json.loads(report_path.read_text(encoding="utf-8"))
        if report["status"] != "passed":
            raise RuntimeError("expected passed benchmark status")
        if report["selected_case_count"] != 2:
            raise RuntimeError("expected two selected cases")
        if report["measured_case_runs"] != 2:
            raise RuntimeError("expected two measured case runs")
        if report["adapter_latency_seconds"]["cases_per_second"] is None:
            raise RuntimeError("missing adapter throughput")

        subprocess.run(
            [
                sys.executable,
                str(SUMMARY),
                "--json-out",
                str(summary_path),
                "--markdown-out",
                str(summary_markdown_path),
                str(report_path),
            ],
            cwd=ROOT,
            check=True,
        )

        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        if not summary["comparable"]:
            raise RuntimeError("single-report summary should be comparable")
        if len(summary["benchmarks"]) != 1:
            raise RuntimeError("expected one summarized benchmark")

    print("semantic benchmark smoke OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
