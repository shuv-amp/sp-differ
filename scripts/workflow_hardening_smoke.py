#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Smoke-test the workflow hardening checker against good and bad fixtures."""

import textwrap
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts" / "check_workflow_hardening.py"
PINNED_REF = "de0fac2e4500dabe0009e67214ff5f5447ce83dd"


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_workflow_hardening", CHECKER)
    if spec is None or spec.loader is None:
        raise SystemExit("failed to load workflow hardening checker")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    checker = _load_checker()

    good = textwrap.dedent(
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
    )
    bad = textwrap.dedent(
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
    )

    good_findings = checker.scan_text(good)
    if good_findings:
        raise SystemExit("good workflow fixture unexpectedly failed: {}".format(good_findings))

    bad_findings = checker.scan_text(bad)
    if not bad_findings:
        raise SystemExit("bad workflow fixture unexpectedly passed")

    required_tokens = {
        "missing_cancel_in_progress",
        "missing_top_level_permissions",
        "unpinned_action_ref",
    }
    observed_tokens = {rule_name for _, rule_name, _ in bad_findings}
    missing_tokens = sorted(required_tokens - observed_tokens)
    if missing_tokens:
        raise SystemExit("missing expected failure token: {}".format(", ".join(missing_tokens)))

    print("workflow hardening smoke OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
