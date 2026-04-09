#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run clang-tidy across a curated list of repository translation units."""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List


ROOT = Path(__file__).resolve().parents[1]
CURATED_SOURCES = (
    "src/runner/sp_differ_runner.cpp",
    "src/runner/sp_differ_compare.cpp",
    "src/cli/main.cpp",
    "src/runner/worker.cpp",
    "src/runner/semantic_bridge.cpp",
    "src/runner/semantic_encoding.cpp",
    "src/runner/semantic_json.cpp",
    "src/runner/semantic_contract.cpp",
    "src/reporter/reporter.cpp",
    "src/core/io.cpp",
    "src/core/case.cpp",
    "src/core/validate.cpp",
    "workers/cpp/sp_differ_worker.cpp",
)


def _default_compile_args() -> List[str]:
    args = ["-std=c++17", "-pthread"]
    homebrew_include = Path("/opt/homebrew/include")
    openssl_include = Path("/opt/homebrew/Cellar/openssl@3/3.6.1/include")
    if homebrew_include.is_dir():
        args.append("-I{}".format(homebrew_include))
    if openssl_include.is_dir():
        args.append("-I{}".format(openssl_include))
    return args


def _resolve_sources(selection: Iterable[str]) -> List[Path]:
    items = list(selection) or list(CURATED_SOURCES)
    return [ROOT / item for item in items]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run clang-tidy across tracked repository sources")
    parser.add_argument(
        "--source",
        action="append",
        choices=CURATED_SOURCES,
        default=[],
        help="Repository translation unit to analyze. Defaults to the full curated list.",
    )
    args = parser.parse_args()

    clang_tidy = shutil.which("clang-tidy")
    if clang_tidy is None:
        print("clang-tidy executable not found in PATH", file=sys.stderr)
        return 1

    compile_args = _default_compile_args()
    failures = []
    for source in _resolve_sources(args.source):
        command = [clang_tidy, str(source), "--", *compile_args]
        print("$ {}".format(" ".join(command)))
        result = subprocess.run(command, cwd=ROOT, check=False)
        if result.returncode != 0:
            failures.append((source, result.returncode))

    if failures:
        print("clang-tidy failed for {} translation unit(s)".format(len(failures)), file=sys.stderr)
        for source, returncode in failures:
            print("  {} (exit {})".format(source, returncode), file=sys.stderr)
        return 1

    print("clang-tidy OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
