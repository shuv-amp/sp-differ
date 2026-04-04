#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fail on unsupported hype or unsupported future-tense wording in public-facing repo text."""

import argparse
import re
import sys
from pathlib import Path


DEFAULT_TARGETS = [
    "README.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "docs",
    "scripts/README.md",
    "scripts/bip352_research_scorecard.py",
    ".github/PULL_REQUEST_TEMPLATE.md",
]

SCAN_SUFFIXES = {".md", ".py"}

CHECKS = [
    (
        "hype_phrase",
        re.compile(r"\b(?:goated|world-class|state[- ]of[- ]the[- ]art|killer|revolutionary|amazing)\b", re.IGNORECASE),
        "Replace marketing language with a measurable claim.",
    ),
    (
        "unsupported_superlative",
        re.compile(
            r"\b(?:best comparison points|best implementation overall|best available in this lab|best on the whole internet|best cost-benefit|globally fastest)\b",
            re.IGNORECASE,
        ),
        "Replace with narrower evidence-backed wording.",
    ),
    (
        "future_tense_claim",
        re.compile("\\b(?:will con" "tain|will be relea" "sed|once the implementation lands)\\b", re.IGNORECASE),
        "Describe the current repository state instead of future-tense release copy.",
    ),
    (
        "empty_certainty",
        re.compile(r"\b(?:obviously|clearly|definitely)\b", re.IGNORECASE),
        "Remove certainty adverb and point to evidence.",
    ),
]


def _iter_files(targets):
    for raw_target in targets:
        path = Path(raw_target)
        if not path.exists():
            raise FileNotFoundError("missing path: {}".format(path))
        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file() and child.suffix in SCAN_SUFFIXES:
                    yield child
        elif path.suffix in SCAN_SUFFIXES:
            yield path


def scan_text(text):
    findings = []
    in_code_fence = False
    for line_no, line in enumerate(text.splitlines(), start=1):
        if line.strip().startswith("```"):
            in_code_fence = not in_code_fence
            continue
        if in_code_fence:
            continue
        for name, pattern, guidance in CHECKS:
            match = pattern.search(line)
            if match is None:
                continue
            findings.append(
                {
                    "rule": name,
                    "line": line_no,
                    "token": match.group(0),
                    "guidance": guidance,
                }
            )
    return findings


def main():
    parser = argparse.ArgumentParser(description="Check repo text for unsupported claims and unsupported future-tense wording")
    parser.add_argument("paths", nargs="*", default=DEFAULT_TARGETS, help="Files or directories to scan")
    args = parser.parse_args()

    failures = []
    for path in _iter_files(args.paths):
        text = path.read_text(encoding="utf-8")
        findings = scan_text(text)
        if findings:
            failures.append((path, findings))

    if failures:
        print("claim discipline check failed")
        for path, findings in failures:
            for finding in findings:
                print(
                    "{}:{}: [{}] {!r} -> {}".format(
                        path,
                        finding["line"],
                        finding["rule"],
                        finding["token"],
                        finding["guidance"],
                    )
                )
        return 1

    print("claim discipline OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
