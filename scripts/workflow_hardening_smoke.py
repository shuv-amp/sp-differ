#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Smoke-test the workflow hardening checker against good and bad fixtures."""

import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts" / "check_workflow_hardening.py"
PINNED_REF = "de0fac2e4500dabe0009e67214ff5f5447ce83dd"


def _run(*paths):
    return subprocess.run(
        [sys.executable, str(CHECKER), *[str(path) for path in paths]],
        capture_output=True,
        text=True,
        check=False,
    )


def main():
    with tempfile.TemporaryDirectory(prefix="sp_differ_workflow_hardening_") as temp_dir:
        root = Path(temp_dir)
        good = root / "good.yml"
        bad = root / "bad.yml"

        good.write_text(
            textwrap.dedent(
                """\
                name: Good
                on:
                  push:
                    branches: ["main"]
                concurrency:
                  group: ${{ github.workflow }}-${{ github.ref }}
                  cancel-in-progress: true
                permissions:
                  contents: read
                jobs:
                  build:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: actions/checkout@{ref}
                """.format(ref=PINNED_REF)
            ),
            encoding="utf-8",
        )

        bad.write_text(
            textwrap.dedent(
                """\
                name: Bad
                on:
                  pull_request:
                    branches: ["main"]
                concurrency:
                  group: ci-${{ github.ref }}
                jobs:
                  build:
                    runs-on: ubuntu-latest
                    steps:
                      - uses: actions/checkout@v6
                """
            ),
            encoding="utf-8",
        )

        good_run = _run(good)
        if good_run.returncode != 0:
            print(good_run.stdout, end="")
            print(good_run.stderr, end="", file=sys.stderr)
            raise SystemExit("good workflow fixture unexpectedly failed")

        bad_run = _run(bad)
        if bad_run.returncode == 0:
            raise SystemExit("bad workflow fixture unexpectedly passed")

        required_tokens = [
            "missing_cancel_in_progress",
            "missing_top_level_permissions",
            "unpinned_action_ref",
        ]
        for token in required_tokens:
            if token not in bad_run.stdout:
                raise SystemExit("missing expected failure token: {}".format(token))

    print("workflow hardening smoke OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
