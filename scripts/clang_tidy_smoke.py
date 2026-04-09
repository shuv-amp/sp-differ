#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Smoke-test the clang-tidy wrapper with a fake executable."""

import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RUNNER = ROOT / "scripts" / "run_clang_tidy.py"


def main():
    with tempfile.TemporaryDirectory(prefix="sp_differ_clang_tidy_smoke_") as temp_dir:
        root = Path(temp_dir)
        fake_tidy = root / "clang-tidy"
        log_path = root / "clang-tidy.log"
        fake_tidy.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' \"$@\" > \"$SP_DIFFER_CLANG_TIDY_LOG\"\n",
            encoding="utf-8",
        )
        fake_tidy.chmod(fake_tidy.stat().st_mode | stat.S_IXUSR)

        env = dict(os.environ)
        env["SP_DIFFER_CLANG_TIDY_LOG"] = str(log_path)
        env["PATH"] = "{}{}{}".format(root, os.pathsep, env.get("PATH", ""))
        result = subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                "--source",
                "src/core/io.cpp",
            ],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
        if result.returncode != 0:
            print(result.stdout, end="")
            print(result.stderr, end="", file=sys.stderr)
            raise SystemExit("run_clang_tidy.py smoke unexpectedly failed")

        logged_args = log_path.read_text(encoding="utf-8").splitlines()
        expected_source = str(ROOT / "src" / "core" / "io.cpp")
        if not logged_args:
            raise SystemExit("fake clang-tidy was not invoked")
        if logged_args[0] != expected_source:
            raise SystemExit("unexpected clang-tidy source path: {}".format(logged_args[0]))
        if len(logged_args) < 3 or logged_args[1] != "--" or "-std=c++17" not in logged_args[2:]:
            raise SystemExit("unexpected clang-tidy argument forwarding: {}".format(logged_args))

    print("clang-tidy smoke OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
