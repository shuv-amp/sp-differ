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
        fake_tidy = root / "fake-clang-tidy"
        log_path = root / "clang-tidy.log"
        source_path = root / "sample.cpp"
        source_path.write_text("int main() { return 0; }\n", encoding="utf-8")
        fake_tidy.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' \"$@\" > \"$SP_DIFFER_CLANG_TIDY_LOG\"\n",
            encoding="utf-8",
        )
        fake_tidy.chmod(fake_tidy.stat().st_mode | stat.S_IXUSR)

        env = dict(os.environ)
        env["SP_DIFFER_CLANG_TIDY_LOG"] = str(log_path)
        result = subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                "--clang-tidy",
                str(fake_tidy),
                "--source",
                str(source_path),
                "--",
                "-std=c++17",
                "-I/tmp/include",
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
        expected = [str(source_path), "--", "-std=c++17", "-I/tmp/include"]
        if logged_args != expected:
            raise SystemExit("unexpected clang-tidy argument forwarding: {}".format(logged_args))

    print("clang-tidy smoke OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
