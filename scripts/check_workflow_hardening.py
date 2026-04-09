#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check GitHub Actions workflows for pinned actions and top-level hardening defaults."""

import argparse
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOT = ROOT / ".github" / "workflows"
WORKFLOW_SUFFIXES = {".yml", ".yaml"}
FULL_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
USES_PATTERN = re.compile(r"^\s*(?:-\s*)?uses:\s*([^@\s#]+)@([^\s#]+)")
TOP_LEVEL_KEY_PATTERN = r"^{}:\s*(.*?)\s*(?:#.*)?$"
BLOCK_KEY_PATTERN = r"^\s+{}:\s*(.*?)\s*(?:#.*)?$"


def _iter_workflow_files():
    if not WORKFLOW_ROOT.is_dir():
        raise FileNotFoundError("missing path: {}".format(WORKFLOW_ROOT))
    for child in sorted(WORKFLOW_ROOT.rglob("*")):
        if child.is_file() and child.suffix in WORKFLOW_SUFFIXES:
            yield child


def _collect_top_level_block(lines, key):
    key_pattern = re.compile(TOP_LEVEL_KEY_PATTERN.format(re.escape(key)))
    for index, line in enumerate(lines):
        match = key_pattern.match(line)
        if match is None:
            continue
        inline_value = match.group(1).strip()
        block_lines = []
        for next_index in range(index + 1, len(lines)):
            next_line = lines[next_index]
            stripped = next_line.strip()
            if stripped and not next_line.startswith((" ", "\t")) and not stripped.startswith("#"):
                break
            block_lines.append((next_index + 1, next_line))
        return index + 1, inline_value, block_lines
    return None, None, None


def _find_block_value(block_lines, key):
    key_pattern = re.compile(BLOCK_KEY_PATTERN.format(re.escape(key)))
    for line_no, line in block_lines:
        match = key_pattern.match(line)
        if match is not None:
            return line_no, match.group(1).strip()
    return None, None


def _inline_map_has_value(inline_value, key, expected_value=None):
    if not inline_value.startswith("{") or not inline_value.endswith("}"):
        return False
    inner = inline_value[1:-1]
    for entry in inner.split(","):
        if ":" not in entry:
            continue
        raw_key, raw_value = entry.split(":", 1)
        if raw_key.strip() != key:
            continue
        if expected_value is None:
            return True
        return raw_value.strip().strip("'\"") == expected_value
    return False


def _is_external_action(source):
    if source.startswith("./") or source.startswith("docker://"):
        return False
    return bool(re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/.+)?$", source))


def scan_text(text):
    findings = []
    lines = text.splitlines()

    concurrency_line, concurrency_inline, concurrency_block = _collect_top_level_block(lines, "concurrency")
    if concurrency_line is None:
        findings.append((1, "missing_top_level_concurrency", "Add a top-level concurrency block with group and cancel-in-progress."))
    else:
        group_line, group_value = _find_block_value(concurrency_block, "group")
        cancel_line, cancel_value = _find_block_value(concurrency_block, "cancel-in-progress")
        if group_line is None and not _inline_map_has_value(concurrency_inline, "group"):
            findings.append(
                (
                    concurrency_line,
                    "missing_concurrency_group",
                    "Add a workflow-level concurrency group so overlapping runs do not collide across pushes.",
                )
            )
        if cancel_line is None and not _inline_map_has_value(concurrency_inline, "cancel-in-progress"):
            findings.append(
                (
                    concurrency_line,
                    "missing_cancel_in_progress",
                    "Declare cancel-in-progress in the top-level concurrency block.",
                )
            )
        elif cancel_line is not None and not cancel_value:
            findings.append(
                (
                    cancel_line,
                    "empty_cancel_in_progress",
                    "Set cancel-in-progress explicitly instead of leaving the field blank.",
                )
            )
        elif group_line is not None and not group_value:
            findings.append(
                (
                    group_line,
                    "empty_concurrency_group",
                    "Set the workflow-level concurrency group explicitly instead of leaving the field blank.",
                )
            )

    permissions_line, permissions_inline, permissions_block = _collect_top_level_block(lines, "permissions")
    if permissions_line is None:
        findings.append((1, "missing_top_level_permissions", "Add a top-level permissions block with contents: read."))
    else:
        contents_line, contents_value = _find_block_value(permissions_block, "contents")
        has_inline_contents_read = _inline_map_has_value(permissions_inline, "contents", "read")
        if contents_line is None and not has_inline_contents_read:
            findings.append(
                (
                    permissions_line,
                    "missing_contents_read",
                    "Set contents: read at the workflow level so unspecified token scopes collapse to none.",
                )
            )
        elif contents_line is not None and contents_value != "read":
            findings.append(
                (
                    contents_line,
                    "unexpected_contents_permission",
                    "Set workflow-level contents permission to read unless a narrower or broader scope is intentionally justified elsewhere.",
                )
            )

    for line_no, line in enumerate(lines, start=1):
        match = USES_PATTERN.match(line)
        if match is None:
            continue
        source, ref = match.groups()
        if not _is_external_action(source):
            continue
        if FULL_SHA_PATTERN.match(ref) is None:
            findings.append(
                (
                    line_no,
                    "unpinned_action_ref",
                    "Pin external actions to a full 40-character commit SHA instead of a mutable tag or branch.",
                )
            )

    return findings


def main():
    argparse.ArgumentParser(
        description="Check GitHub Actions workflows for pinned actions and top-level hardening defaults"
    ).parse_args()

    failures = []
    for path in _iter_workflow_files():
        text = path.read_text(encoding="utf-8")
        findings = scan_text(text)
        if findings:
            failures.append((path, findings))

    if failures:
        print("workflow hardening check failed")
        for path, findings in failures:
            for line_no, rule_name, guidance in findings:
                print("{}:{}: [{}] {}".format(path, line_no, rule_name, guidance))
        return 1

    print("workflow hardening OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
