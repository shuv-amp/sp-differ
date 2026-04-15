#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check repo-owned source comments for deferred-note markers and hype."""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


DEFAULT_TARGETS = ["src", "workers", "scripts", "adapters", "tests/fixtures"]
SOURCE_SUFFIXES = {".py", ".cpp", ".h", ".hpp", ".cc", ".cxx", ".rs", ".go"}
SKIP_PARTS = {"build", "target", "__pycache__"}
SKIP_PREFIXES = [
    Path("tests/vectors/bip352/official/reference"),
]

DEFERRED_NOTE_TOKENS = ("TO" "DO", "FIX" "ME", "XXX", "HACK")

CHECKS = [
    (
        "todo_marker",
        re.compile(r"\b(?:{}|{}|{}|{})\b".format(*DEFERRED_NOTE_TOKENS)),
        "Resolve the note or move it into an issue/reference outside the source comment.",
    ),
    (
        "hype_without_evidence",
        re.compile(r"\b(?:robust|comprehensive|seamless|world-class|goated|killer|amazing|revolutionary)\b", re.IGNORECASE),
        "Replace hype with a concrete technical statement.",
    ),
    (
        "vague_certainty",
        re.compile(r"\b(?:obviously|clearly|definitely)\b", re.IGNORECASE),
        "Remove certainty wording and keep the comment factual.",
    ),
]


def _should_skip(path: Path) -> bool:
    if any(part in SKIP_PARTS for part in path.parts):
        return True
    return any(path.is_relative_to((ROOT / prefix).resolve()) for prefix in SKIP_PREFIXES)


def _iter_files(targets):
    for raw_target in targets:
        candidate = Path(raw_target)
        if candidate.is_absolute():
            try:
                candidate = candidate.relative_to(ROOT)
            except ValueError as exc:
                raise ValueError("path escapes repository root: {}".format(raw_target)) from exc
        if any(part == ".." for part in candidate.parts):
            raise ValueError("path escapes repository root: {}".format(raw_target))
        path = ROOT / candidate
        if path.is_symlink():
            raise ValueError("path escapes repository root: {}".format(raw_target))
        if not path.exists():
            raise FileNotFoundError("missing path: {}".format(path))
        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_symlink():
                    raise ValueError("path escapes repository root: {}".format(child))
                if not child.is_file():
                    continue
                if child.suffix not in SOURCE_SUFFIXES or _should_skip(child):
                    continue
                yield child
        elif path.is_file() and path.suffix in SOURCE_SUFFIXES and not _should_skip(path):
            yield path


def _scan_python(text: str):
    doc_delim = None
    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.lstrip()
        if doc_delim is not None:
            yield line_no, stripped
            if doc_delim in stripped:
                doc_delim = None
            continue
        if stripped.startswith("#!") or stripped.startswith("# pylint:"):
            continue
        if stripped.startswith("#"):
            yield line_no, stripped[1:].strip()
            continue
        if stripped.startswith('"""') or stripped.startswith("'''"):
            delim = stripped[:3]
            yield line_no, stripped
            if stripped.count(delim) < 2:
                doc_delim = delim


def _trim_comment_prefix(text: str) -> str:
    trimmed = text.lstrip()
    for prefix in ("///", "//!", "//", "/*", "*", "*/"):
        if trimmed.startswith(prefix):
            return trimmed[len(prefix) :].strip()
    return trimmed


def _scan_c_like(text: str):
    in_block = False
    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.lstrip()
        if in_block:
            yield line_no, _trim_comment_prefix(stripped)
            if "*/" in stripped:
                in_block = False
            continue
        if stripped.startswith("//"):
            yield line_no, _trim_comment_prefix(stripped)
            continue
        if stripped.startswith("/*"):
            yield line_no, _trim_comment_prefix(stripped)
            if "*/" not in stripped:
                in_block = True


def _scan_comments(path: Path, text: str):
    if path.suffix == ".py":
        yield from _scan_python(text)
        return
    yield from _scan_c_like(text)


def collect_failures(targets):
    failures = []
    for path in _iter_files(targets):
        text = path.read_text(encoding="utf-8")
        findings = []
        for line_no, comment_text in _scan_comments(path, text):
            for rule_name, pattern, guidance in CHECKS:
                match = pattern.search(comment_text)
                if match is None:
                    continue
                findings.append((line_no, rule_name, match.group(0), guidance))
        if findings:
            failures.append((path, findings))
    return failures


def main():
    failures = collect_failures(DEFAULT_TARGETS)
    if failures:
        print("source comment discipline check failed")
        for path, findings in failures:
            for line_no, rule_name, token, guidance in findings:
                print("{}:{}: [{}] {!r} -> {}".format(path, line_no, rule_name, token, guidance))
        return 1

    print("source comment discipline OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
