#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the compiled runner against the derived official BIP352 subset."""

import argparse
import json
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SP-DIFFER smoke checks on derived official vectors")
    parser.add_argument(
        "--runner",
        type=Path,
        default=Path("build/sp_differ_runner"),
        help="Path to the compiled SP-DIFFER runner",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("tests/vectors/bip352/derived/v1/manifest.json"),
        help="Path to the derived case manifest",
    )
    parser.add_argument(
        "--worker",
        default="cpp",
        help="Worker argument to pass through to sp_differ_runner (--worker)",
    )
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    base_dir = args.manifest.parent
    cases = manifest.get("cases", [])
    if not isinstance(cases, list) or not cases:
        print("error: manifest has no cases", file=sys.stderr)
        return 2

    for case in cases:
        case_path = base_dir / case["path"]
        cmd = [str(args.runner), str(case_path), "--worker", args.worker]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print("FAIL: {}".format(case_path), file=sys.stderr)
            stderr = result.stderr.strip()
            stdout = result.stdout.strip()
            if stderr:
                print(stderr, file=sys.stderr)
            if stdout:
                print(stdout, file=sys.stderr)
            return 2

    print("OK: {} derived official vector cases validated with worker {}".format(len(cases), args.worker))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
