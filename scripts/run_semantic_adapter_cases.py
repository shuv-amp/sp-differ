#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run a semantic adapter against the derived v2 corpus."""

import argparse
import json
import shlex
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from bip352_reference import verify_reference_manifest
from bip352_vectors import write_json
from semantic_adapter import build_semantic_request, validate_semantic_request
from semantic_case_runner import build_adapter_command, read_case_v2, run_adapter
from semantic_contract import compare_semantic_results, validate_semantic_result

ROOT = Path(__file__).resolve().parents[1]
REGRESSION_INTAKE_HELPER = ROOT / "scripts" / "intake_semantic_regressions.py"


def _render_markdown_report(report: Dict[str, Any]) -> str:
    lines = [
        "# Semantic Adapter Report",
        "",
        "- adapter: `{}`".format(report["adapter_name"]),
        "- status: `{}`".format(report["status"]),
        "- upstream_commit: `{}`".format(report["upstream_commit"]),
        "- snapshot_sha256: `{}`".format(report["snapshot_sha256"]),
        "- cases: `{}`".format(report["derived_case_count"]),
        "- skipped: `{}`".format(report.get("skipped_case_count", 0)),
        "- passed: `{}`".format(report["passed_case_count"]),
        "- failed: `{}`".format(report["failed_case_count"]),
        "",
    ]
    failures = report.get("failures", [])
    if not failures:
        lines.append("No failures.")
        lines.append("")
        return "\n".join(lines)

    lines.extend(
        [
            "## Failures",
            "",
        ]
    )
    for failure in failures:
        lines.append("### `{}`".format(failure["id"]))
        lines.append("")
        lines.append("- kind: `{}`".format(failure["kind"]))
        lines.append("- errors: `{}`".format("; ".join(failure["errors"])))
        if failure.get("expectation_mode"):
            lines.append("- expectation_mode: `{}`".format(failure["expectation_mode"]))
        if failure.get("artifact_dir"):
            lines.append("- artifact_dir: `{}`".format(failure["artifact_dir"]))
        if failure.get("repro_cmd"):
            lines.append("- replay: `{}`".format(failure["repro_cmd"]))
        if failure.get("intake_cmd"):
            lines.append("- promote: `{}`".format(failure["intake_cmd"]))
        lines.append("")
    return "\n".join(lines)


def _case_targets_adapter(item: Dict[str, Any], adapter_name: str) -> bool:
    target = item.get("adapter_name")
    if target is not None:
        if not isinstance(target, str) or not target:
            raise RuntimeError(
                "manifest case {} has invalid adapter_name".format(item.get("id", "<unknown>"))
            )
        return target == adapter_name

    targets = item.get("adapter_names")
    if targets is None:
        return True
    if not isinstance(targets, list) or not targets or not all(
        isinstance(value, str) and value for value in targets
    ):
        raise RuntimeError(
            "manifest case {} has invalid adapter_names".format(item.get("id", "<unknown>"))
        )
    return adapter_name in targets


def _write_failure_artifacts(
    artifact_dir: Path,
    failure_id: str,
    adapter_name: str,
    repro_target_args: List[str],
    official_manifest: Path,
    official_vectors: Path,
    manifest_path: Path,
    timeout_seconds: float,
    case_path: Optional[Path],
    expectation_path: Path,
    request: Dict[str, Any],
    expected: Dict[str, Any],
    actual: Optional[Dict[str, Any]],
    errors: List[str],
) -> Path:
    failure_dir = artifact_dir / failure_id
    failure_dir.mkdir(parents=True, exist_ok=True)
    request_path = failure_dir / "request.json"
    expected_path = failure_dir / "expected.json"
    actual_path = failure_dir / "actual.json"
    summary_path = failure_dir / "summary.json"
    replay_path = failure_dir / "replay.sh"
    promote_path = failure_dir / "promote.sh"
    case_copy_path = failure_dir / "case.hex"

    request_path.write_text(json.dumps(request, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    expected_path.write_text(json.dumps(expected, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if actual is not None:
        actual_path.write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if case_path is not None:
        case_copy_path.write_text(case_path.read_text(encoding="ascii"), encoding="ascii")

    repro_cmd = [
        "python3",
        "scripts/run_semantic_adapter_cases.py",
        "--adapter-name",
        adapter_name,
        *repro_target_args,
        "--official-manifest",
        str(official_manifest),
        "--official-vectors",
        str(official_vectors),
        "--manifest",
        str(manifest_path),
        "--case-id",
        failure_id,
        "--timeout-seconds",
        str(timeout_seconds),
        "--json-out",
        str(summary_path.with_name("replay_report.json")),
    ]
    intake_cmd = [
        "python3",
        "scripts/intake_semantic_regressions.py",
        "--artifact-dir",
        str(failure_dir),
    ]
    summary = {
        "id": failure_id,
        "adapter_name": adapter_name,
        "repro_target_args": repro_target_args,
        "official_manifest": str(official_manifest),
        "official_vectors": str(official_vectors),
        "manifest_path": str(manifest_path),
        "timeout_seconds": timeout_seconds,
        "case_path": None if case_path is None else str(case_path),
        "expectation_path": str(expectation_path),
        "request_path": str(request_path),
        "expected_path": str(expected_path),
        "actual_path": str(actual_path) if actual is not None else None,
        "errors": errors,
        "repro_cmd": shlex.join(repro_cmd),
        "intake_cmd": shlex.join(intake_cmd),
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    replay_path.write_text(
        "#!/bin/sh\nset -eu\n{}\n".format(shlex.join(repro_cmd)),
        encoding="utf-8",
    )
    replay_path.chmod(0o755)
    promote_path.write_text(
        "#!/bin/sh\nset -eu\n{}\n".format(shlex.join(intake_cmd)),
        encoding="utf-8",
    )
    promote_path.chmod(0o755)
    return failure_dir


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a semantic adapter against derived v2 cases")
    parser.add_argument(
        "--adapter-name",
        required=True,
        help="Human-readable adapter name for reporting",
    )
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "--adapter-cmd",
        help="Shell-style command used to execute the adapter",
    )
    target_group.add_argument(
        "--worker-lib",
        type=Path,
        help="Path to semantic worker shared library",
    )
    parser.add_argument(
        "--official-manifest",
        type=Path,
        default=Path("tests/vectors/bip352/official/manifest.json"),
        help="Path to the vendored official manifest",
    )
    parser.add_argument(
        "--official-vectors",
        type=Path,
        default=Path("tests/vectors/bip352/official/send_and_receive_test_vectors.json"),
        help="Path to the vendored official vector snapshot",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("tests/vectors/bip352/derived/v2/manifest.json"),
        help="Path to the derived v2 manifest",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=Path("build/semantic_adapter_report.json"),
        help="Where to write the machine-readable compare report",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=30.0,
        help="Per-case adapter execution timeout in seconds",
    )
    parser.add_argument(
        "--case-id",
        help="Optional derived case id to run instead of the full manifest",
    )
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        help="Optional directory for per-failure replay artifacts",
    )
    parser.add_argument(
        "--markdown-out",
        type=Path,
        help="Optional markdown summary path",
    )
    parser.add_argument(
        "--allow-empty",
        action="store_true",
        help="Treat an empty manifest as a successful no-op run",
    )
    args = parser.parse_args()

    try:
        official_manifest, verification, _ = verify_reference_manifest(
            args.official_manifest, args.official_vectors
        )
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        manifest_cases = manifest.get("cases", [])
        if not isinstance(manifest_cases, list):
            raise RuntimeError("manifest cases must be a list")
        total_case_count = len(manifest_cases)
        cases = manifest_cases
        if not isinstance(cases, list):
            raise RuntimeError("manifest cases must be a list")
        if args.case_id:
            cases = [item for item in cases if item.get("id") == args.case_id]
            if not cases:
                raise RuntimeError("unknown case id: {}".format(args.case_id))
            skipped_case_count = 0
        elif not cases and not args.allow_empty:
            raise RuntimeError("manifest has no cases")
        else:
            cases = [item for item in cases if _case_targets_adapter(item, args.adapter_name)]
            skipped_case_count = total_case_count - len(cases)
            if not cases and not args.allow_empty:
                raise RuntimeError(
                    "manifest has no cases for adapter {}".format(args.adapter_name)
                )
        adapter_cmd, repro_target_args = build_adapter_command(args.adapter_cmd, args.worker_lib)
    except Exception as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2

    if args.artifact_dir is not None and args.artifact_dir.exists():
        shutil.rmtree(args.artifact_dir)

    failures: List[Dict[str, Any]] = []
    passed = 0
    for item in cases:
        case_path_value = item.get("path")
        case_path = None
        if isinstance(case_path_value, str):
            case_path = args.manifest.parent / case_path_value
        expectation_path = args.manifest.parent / item["expectation_path"]
        request_path_value = item.get("request_path")
        request_path = None
        if isinstance(request_path_value, str):
            request_path = args.manifest.parent / request_path_value
        expectation_mode = item.get("expectation_mode", "oracle")
        if expectation_mode not in ("oracle", "observed_actual"):
            failures.append(
                {
                    "id": item.get("id", "<unknown>"),
                    "kind": item.get("kind", "<unknown>"),
                    "case_path": None if case_path is None else str(case_path),
                    "expectation_path": str(expectation_path),
                    "errors": ["unknown expectation_mode: {}".format(expectation_mode)],
                    "expectation_mode": expectation_mode,
                    "actual": None,
                    "artifact_dir": None,
                    "repro_cmd": None,
                    "intake_cmd": None,
                }
            )
            continue
        expected = None
        tracked_actual = None
        request = None
        try:
            expected = validate_semantic_result(
                json.loads(expectation_path.read_text(encoding="utf-8"))
            )
            if request_path is not None:
                request = validate_semantic_request(
                    json.loads(request_path.read_text(encoding="utf-8"))
                )
            else:
                if case_path is None:
                    raise RuntimeError("manifest case is missing both path and request_path")
                case = read_case_v2(case_path)
                expectation_hints = None
                if item["kind"] == "receive":
                    expectation_hints = {
                        "detailed_outputs_required": bool(
                            expected.get("detailed_outputs_available", True)
                        )
                    }
                request = build_semantic_request(
                    item["kind"], case, expected["source"], expectation_hints=expectation_hints
                )
            if expectation_mode == "observed_actual":
                observed_actual_path_value = item.get("observed_actual_path")
                if not isinstance(observed_actual_path_value, str):
                    raise RuntimeError(
                        "manifest case {} is missing observed_actual_path".format(
                            item.get("id", "<unknown>")
                        )
                    )
                tracked_actual = validate_semantic_result(
                    json.loads(
                        (args.manifest.parent / observed_actual_path_value).read_text(
                            encoding="utf-8"
                        )
                    )
                )
        except Exception as exc:
            failures.append(
                {
                    "id": item.get("id", "<unknown>"),
                    "kind": item.get("kind", "<unknown>"),
                    "case_path": None if case_path is None else str(case_path),
                    "expectation_path": str(expectation_path),
                    "errors": ["case setup failed: {}".format(exc)],
                    "expectation_mode": expectation_mode,
                    "actual": None,
                    "artifact_dir": None,
                    "repro_cmd": None,
                    "intake_cmd": None,
                }
            )
            continue

        try:
            actual = validate_semantic_result(
                run_adapter(adapter_cmd, request, args.timeout_seconds)
            )
            oracle_errors = compare_semantic_results(expected, actual)
            if tracked_actual is not None:
                tracked_errors = compare_semantic_results(tracked_actual, actual)
                if not tracked_errors:
                    errors = []
                elif not oracle_errors:
                    errors = [
                        "tracked divergence no longer reproduces: adapter now matches oracle"
                    ]
                else:
                    errors = [
                        "tracked divergence changed: {}".format("; ".join(tracked_errors)),
                        "current oracle delta: {}".format("; ".join(oracle_errors)),
                    ]
            else:
                errors = oracle_errors
        except Exception as exc:
            errors = ["adapter execution failed: {}".format(exc)]
            actual = None

        if errors:
            failure_artifact_dir = None
            repro_cmd = None
            intake_cmd = None
            if args.artifact_dir is not None:
                failure_artifact_dir = _write_failure_artifacts(
                    args.artifact_dir,
                    item["id"],
                    args.adapter_name,
                    repro_target_args,
                    args.official_manifest,
                    args.official_vectors,
                    args.manifest,
                    args.timeout_seconds,
                    case_path,
                    expectation_path,
                    request,
                    expected,
                    actual,
                    errors,
                )
                summary = json.loads(
                    (failure_artifact_dir / "summary.json").read_text(encoding="utf-8")
                )
                repro_cmd = summary["repro_cmd"]
                intake_cmd = summary["intake_cmd"]
            failures.append(
                {
                    "id": item["id"],
                    "kind": item["kind"],
                    "case_path": None if case_path is None else str(case_path),
                    "expectation_path": str(expectation_path),
                    "errors": errors,
                    "expectation_mode": expectation_mode,
                    "actual": actual,
                    "artifact_dir": None if failure_artifact_dir is None else str(failure_artifact_dir),
                    "repro_cmd": repro_cmd,
                    "intake_cmd": intake_cmd,
                }
            )
        else:
            passed += 1

    processed_case_count = passed + len(failures)
    if processed_case_count != len(cases):
        failures.append(
            {
                "id": "<internal-report-invariant>",
                "kind": "internal",
                "case_path": None,
                "expectation_path": None,
                "errors": [
                    "processed {} cases but manifest selected {}".format(
                        processed_case_count, len(cases)
                    )
                ],
                "actual": None,
                "artifact_dir": None,
                "repro_cmd": None,
                "intake_cmd": None,
            }
        )

    report = {
        "status": "passed" if not failures else "failed",
        "adapter_name": args.adapter_name,
        "adapter_cmd": adapter_cmd,
        "repro_target_args": repro_target_args,
        "upstream_commit": official_manifest.get("upstream_commit"),
        "snapshot_sha256": verification["snapshot_sha256"],
        "derived_manifest": str(args.manifest),
        "derived_case_count": len(cases),
        "skipped_case_count": skipped_case_count,
        "passed_case_count": passed,
        "failed_case_count": len(failures),
        "failures": failures,
    }
    write_json(args.json_out, report)
    if args.markdown_out is not None:
        args.markdown_out.write_text(_render_markdown_report(report) + "\n", encoding="utf-8")

    if failures:
        print("FAIL: semantic adapter compare failed", file=sys.stderr)
        print("  adapter: {}".format(args.adapter_name), file=sys.stderr)
        for failure in failures[:10]:
            print(
                "  {}: {}".format(failure["id"], ", ".join(failure["errors"])),
                file=sys.stderr,
            )
        print("  wrote report: {}".format(args.json_out), file=sys.stderr)
        if args.markdown_out is not None:
            print("  wrote markdown: {}".format(args.markdown_out), file=sys.stderr)
        return 2

    print("semantic adapter compare OK")
    print("  adapter: {}".format(args.adapter_name))
    print("  sha256: {}".format(report["snapshot_sha256"]))
    print("  cases: {}".format(report["derived_case_count"]))
    print("  wrote report: {}".format(args.json_out))
    if args.markdown_out is not None:
        print("  wrote markdown: {}".format(args.markdown_out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
