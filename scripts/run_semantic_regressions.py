#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the tracked semantic regression suite against an adapter or worker."""

import argparse
import shlex
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run_semantic_adapter_cases.py"


def _slugify(value: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in value.lower()).strip("_")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run tracked semantic regressions against an adapter or worker"
    )
    parser.add_argument("--adapter-name", required=True, help="Name used in reports")
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--adapter-cmd", help="Shell-style adapter command")
    target_group.add_argument("--worker-lib", type=Path, help="Path to semantic worker shared library")
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("tests/regressions/semantic/manifest.json"),
        help="Path to the tracked regression manifest",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=30.0,
        help="Per-case timeout in seconds",
    )
    parser.add_argument("--json-out", type=Path, help="Optional JSON report path")
    parser.add_argument("--markdown-out", type=Path, help="Optional markdown report path")
    parser.add_argument("--artifact-dir", type=Path, help="Optional artifact output directory")
    args = parser.parse_args()

    slug = _slugify(args.adapter_name)
    json_out = args.json_out or Path("build/semantic_regressions_{}.json".format(slug))
    markdown_out = args.markdown_out or Path("build/semantic_regressions_{}.md".format(slug))
    artifact_dir = args.artifact_dir or Path("build/semantic_regressions_artifacts") / slug

    command = [
        sys.executable,
        str(RUNNER),
        "--adapter-name",
        args.adapter_name,
        "--manifest",
        str(args.manifest),
        "--timeout-seconds",
        str(args.timeout_seconds),
        "--json-out",
        str(json_out),
        "--markdown-out",
        str(markdown_out),
        "--artifact-dir",
        str(artifact_dir),
        "--allow-empty",
    ]
    if args.worker_lib is not None:
        command.extend(["--worker-lib", str(args.worker_lib)])
    else:
        command.extend(["--adapter-cmd", args.adapter_cmd])

    proc = subprocess.run(command, check=False)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
