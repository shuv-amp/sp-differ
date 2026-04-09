#!/usr/bin/env python3
"""Public CLI for release-oriented SP-DIFFER workflows."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


ROOT = Path(__file__).resolve().parent
DEFAULT_BUILD_DIR = ROOT / "build"
DEFAULT_REGRESSION_MANIFEST = ROOT / "tests" / "regressions" / "semantic" / "manifest.json"
DEFAULT_EXTERNAL_PROBE_CANDIDATES = ROOT / "research" / "bip352_candidates.json"
DEFAULT_EXTERNAL_PROBE = DEFAULT_BUILD_DIR / "bip352_external_probe.json"
DEFAULT_STATUS_JSON = DEFAULT_BUILD_DIR / "sp_differ_release_readiness.json"
DEFAULT_STATUS_MARKDOWN = DEFAULT_BUILD_DIR / "sp_differ_release_readiness.md"

ORACLE_REPORTS: Sequence[Tuple[str, str]] = (
    ("semantic-oracle", "bip352_v2_oracle_compare_report.json"),
)
ADAPTER_REPORTS: Sequence[Tuple[str, str]] = (
    ("reference-adapter", "reference_semantic_adapter_report.json"),
    ("spdk-adapter", "spdk_semantic_adapter_report.json"),
    ("spdk-worker", "spdk_semantic_worker_report.json"),
    ("silent-payments-adapter", "silent_payments_semantic_adapter_report.json"),
    ("silent-payments-worker", "silent_payments_semantic_worker_report.json"),
    ("bip352-adapter", "bip352_semantic_adapter_report.json"),
    ("bip352-worker", "bip352_semantic_worker_report.json"),
    ("go-bip352-adapter", "go_bip352_semantic_adapter_report.json"),
    ("go-bip352-worker", "go_bip352_semantic_worker_report.json"),
    ("bdk-sp-adapter", "bdk_sp_semantic_adapter_report.json"),
)
ERROR_SURFACE_REPORTS: Sequence[Tuple[str, str]] = (
    ("semantic-error-surfaces", "semantic_error_surface_report.json"),
)
REGRESSION_REPORTS: Sequence[Tuple[str, str]] = (
    ("reference-regressions", "semantic_regressions_reference.json"),
    ("spdk-regressions", "semantic_regressions_spdk_rust.json"),
    ("spdk-worker-regressions", "semantic_regressions_spdk_rust_ffi.json"),
    ("silent-payments-regressions", "semantic_regressions_silent_payments.json"),
    ("silent-payments-worker-regressions", "semantic_regressions_silent_payments_ffi.json"),
    ("bip352-regressions", "semantic_regressions_bip352.json"),
    ("bip352-worker-regressions", "semantic_regressions_bip352_ffi.json"),
    ("go-bip352-regressions", "semantic_regressions_go_bip352.json"),
    ("go-bip352-worker-regressions", "semantic_regressions_go_bip352_ffi.json"),
    ("bdk-sp-regressions", "semantic_regressions_bdk_sp.json"),
)
FUZZ_REPORTS: Sequence[Tuple[str, str]] = (
    ("spdk-fuzz", "spdk_semantic_fuzz_report.json"),
    ("silent-payments-fuzz", "silent_payments_semantic_fuzz_report.json"),
    ("bip352-fuzz", "bip352_semantic_fuzz_report.json"),
    ("go-bip352-fuzz", "go_bip352_semantic_fuzz_report.json"),
)
ADAPTER_FUZZ_REPORTS: Sequence[Tuple[str, str]] = (
    ("reference-adapter-fuzz", "reference_semantic_adapter_fuzz_report.json"),
    ("spdk-adapter-fuzz", "spdk_semantic_adapter_fuzz_report.json"),
    (
        "silent-payments-adapter-fuzz",
        "silent_payments_semantic_adapter_fuzz_report.json",
    ),
    ("bip352-adapter-fuzz", "bip352_semantic_adapter_fuzz_report.json"),
    ("go-bip352-adapter-fuzz", "go_bip352_semantic_adapter_fuzz_report.json"),
    ("bdk-sp-adapter-fuzz", "bdk_sp_semantic_adapter_fuzz_report.json"),
)
EXTERNAL_PROBE_CANDIDATES: Sequence[Tuple[str, str]] = (
    ("spdk-rust", "SPDK adapter (silentpayments crate)"),
    ("silent-payments", "silent-payments crate adapter"),
    ("bip352", "bip352 crate adapter"),
    ("go-bip352", "go-bip352 adapter"),
    ("bdk-sp", "BDK bdk-sp"),
)


class SpDifferCliError(Exception):
    pass


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _now_iso8601() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _load_report_item(build_dir: Path, label: str, filename: str) -> Dict[str, Any]:
    path = build_dir / filename
    if not path.exists():
        return {
            "label": label,
            "path": str(path),
            "present": False,
            "status": "missing",
        }
    data = _read_json(path)
    item: Dict[str, Any] = {
        "label": label,
        "path": str(path),
        "present": True,
        "status": data.get("status", "unknown"),
    }
    for key in (
        "adapter_name",
        "worker_lib",
        "upstream_commit",
        "snapshot_sha256",
        "derived_case_count",
        "passed_case_count",
        "failed_case_count",
        "failure_count",
        "seed",
        "structured_iterations",
        "raw_iterations",
        "iterations",
        "max_failures",
        "counts",
    ):
        if key in data:
            item[key] = data[key]
    failures = data.get("failures")
    if isinstance(failures, list) and failures:
        item["failure_ids"] = [entry.get("id", "<unknown>") for entry in failures[:10]]
    return item


def _collect_section(
    build_dir: Path, specs: Sequence[Tuple[str, str]]
) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    items = []
    missing = []
    failed = []
    for label, filename in specs:
        item = _load_report_item(build_dir, label, filename)
        items.append(item)
        if not item["present"]:
            missing.append(filename)
        elif item["status"] != "passed":
            failed.append(label)
    return items, missing, failed


def _tracked_regression_case_count(manifest_path: Path) -> Optional[int]:
    if not manifest_path.exists():
        return None
    data = _read_json(manifest_path)
    cases = data.get("cases")
    if not isinstance(cases, list):
        raise SpDifferCliError("regression manifest cases must be a list")
    return len(cases)


def _expected_case_count(items: Iterable[Dict[str, Any]]) -> Optional[int]:
    counts = sorted(
        {
            int(item["derived_case_count"])
            for item in items
            if item.get("derived_case_count") is not None
        }
    )
    if not counts:
        return None
    if len(counts) > 1:
        raise SpDifferCliError(
            "inconsistent derived_case_count values across reports: {}".format(counts)
        )
    return counts[0]


def _external_probe_markdown_path(path: Path) -> Path:
    if path.suffix:
        return path.with_suffix(".md")
    return Path(str(path) + ".md")


def _resolve_external_probe_paths(
    build_dir: Path,
    external_probe: Optional[Path],
) -> Tuple[Path, Path]:
    json_path = external_probe or (build_dir / DEFAULT_EXTERNAL_PROBE.name)
    return json_path, _external_probe_markdown_path(json_path)


def _build_external_probe_command(
    python: str,
    candidates: Path,
    json_out: Path,
    markdown_out: Path,
) -> List[str]:
    return [
        python,
        str(ROOT / "scripts" / "bip352_external_probe.py"),
        "--candidates",
        str(candidates),
        "--json-out",
        str(json_out),
        "--markdown-out",
        str(markdown_out),
    ]


def _classify_external_probe_item(
    candidate_id: str,
    default_name: str,
    probe: Dict[str, Any],
) -> Dict[str, Any]:
    probe_status = str(probe.get("status", "unknown"))
    version_status = str(probe.get("version_status", "unknown")) or "unknown"
    if probe_status == "failed" or version_status == "stale":
        status = "failed"
    elif version_status == "current":
        status = "passed"
    else:
        # A present release-critical probe that cannot establish freshness is not green.
        status = "failed"

    item: Dict[str, Any] = {
        "label": candidate_id,
        "display_name": str(probe.get("name") or default_name),
        "path": str(probe.get("__path") or ""),
        "present": True,
        "status": status,
        "probe_status": probe_status,
        "version_status": version_status,
    }
    local_pin = probe.get("local_version") or probe.get("local_commit")
    upstream_pin = probe.get("upstream_latest_version") or probe.get("upstream_head")
    if local_pin is not None:
        item["local_pin"] = local_pin
    if upstream_pin is not None:
        item["upstream_pin"] = upstream_pin
    if isinstance(probe.get("summary"), str):
        item["summary"] = probe["summary"]
    return item


def _load_external_probe_section(
    build_dir: Path,
    external_probe: Optional[Path],
) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    path = external_probe
    if path is None:
        auto_path = build_dir / DEFAULT_EXTERNAL_PROBE.name
        if auto_path.exists():
            path = auto_path
    if path is None:
        return None, [
            "No external BIP352 probe found at {}; upstream version freshness was not evaluated.".format(
                build_dir / DEFAULT_EXTERNAL_PROBE.name
            )
        ]
    if not path.exists():
        raise SpDifferCliError("external probe does not exist: {}".format(path))

    data = _read_json(path)
    probes = data.get("probes")
    if not isinstance(probes, list):
        raise SpDifferCliError("external probe document is missing a probes list")

    indexed_probes: Dict[str, Dict[str, Any]] = {}
    for raw_probe in probes:
        if not isinstance(raw_probe, dict):
            continue
        candidate_id = raw_probe.get("candidate")
        if isinstance(candidate_id, str):
            probe = dict(raw_probe)
            probe["__path"] = str(path)
            indexed_probes[candidate_id] = probe

    items: List[Dict[str, Any]] = []
    missing: List[str] = []
    failed: List[str] = []
    for candidate_id, default_name in EXTERNAL_PROBE_CANDIDATES:
        probe = indexed_probes.get(candidate_id)
        if probe is None:
            missing.append(candidate_id)
            items.append(
                {
                    "label": candidate_id,
                    "display_name": default_name,
                    "path": str(path),
                    "present": False,
                    "status": "missing",
                }
            )
            continue
        item = _classify_external_probe_item(candidate_id, default_name, probe)
        items.append(item)
        if item["status"] != "passed":
            failed.append(candidate_id)

    section = {
        "expected_report_count": len(EXTERNAL_PROBE_CANDIDATES),
        "items": items,
        "missing_reports": missing,
        "failed_reports": failed,
        "generated_at": data.get("generated_at"),
        "path": str(path),
    }
    notes = ["Integrated external adapter freshness evaluated from {}".format(path)]
    generated_at = data.get("generated_at")
    if isinstance(generated_at, str) and generated_at:
        notes.append("External BIP352 probe generated_at: {}".format(generated_at))
    return section, notes


def build_release_readiness_report(
    build_dir: Path = DEFAULT_BUILD_DIR,
    regression_manifest: Path = DEFAULT_REGRESSION_MANIFEST,
    profile: str = "release",
    external_probe: Optional[Path] = None,
) -> Dict[str, Any]:
    section_specs: List[Tuple[str, Sequence[Tuple[str, str]]]] = [
        ("oracle", ORACLE_REPORTS),
        ("adapters", ADAPTER_REPORTS),
        ("error_surfaces", ERROR_SURFACE_REPORTS),
        ("regressions", REGRESSION_REPORTS),
    ]
    if profile == "release":
        section_specs.append(("fuzz", FUZZ_REPORTS))
        section_specs.append(("adapter_fuzz", ADAPTER_FUZZ_REPORTS))
    elif profile != "quick":
        raise SpDifferCliError("unknown evidence profile: {}".format(profile))

    sections: Dict[str, Dict[str, Any]] = {}
    all_present_items: List[Dict[str, Any]] = []
    missing_reports: List[str] = []
    failed_reports: List[str] = []
    for section_name, specs in section_specs:
        items, missing, failed = _collect_section(build_dir, specs)
        sections[section_name] = {
            "expected_report_count": len(specs),
            "items": items,
            "missing_reports": missing,
            "failed_reports": failed,
        }
        all_present_items.extend(item for item in items if item["present"])
        missing_reports.extend(missing)
        failed_reports.extend(failed)

    external_section, external_notes = _load_external_probe_section(
        build_dir, external_probe
    )
    if external_section is not None:
        sections["external_probe"] = external_section
        missing_reports.extend(external_section["missing_reports"])
        failed_reports.extend(external_section["failed_reports"])

    snapshot_values = sorted(
        {
            item["snapshot_sha256"]
            for item in all_present_items
            if item.get("snapshot_sha256")
        }
    )
    upstream_values = sorted(
        {
            item["upstream_commit"]
            for item in all_present_items
            if item.get("upstream_commit")
        }
    )

    consistency_errors: List[str] = []
    if len(snapshot_values) > 1:
        consistency_errors.append(
            "inconsistent snapshot_sha256 across reports: {}".format(snapshot_values)
        )
    if len(upstream_values) > 1:
        consistency_errors.append(
            "inconsistent upstream_commit across reports: {}".format(upstream_values)
        )

    semantic_case_count = None
    try:
        semantic_case_count = _expected_case_count(
            sections["oracle"]["items"] + sections["adapters"]["items"]
        )
    except SpDifferCliError as exc:
        consistency_errors.append(str(exc))

    regression_case_count = _tracked_regression_case_count(regression_manifest)

    if consistency_errors or failed_reports:
        overall_status = "failed"
    elif missing_reports:
        overall_status = "incomplete"
    else:
        overall_status = "passed"

    notes = [
        "This report summarizes currently materialized local evidence under build/; longer nightly soak confidence still depends on elapsed scheduled runs."
    ]
    notes.extend(external_notes)
    if regression_case_count == 0:
        notes.append("Tracked semantic regression manifest is currently empty.")

    report = {
        "generated_at": _now_iso8601(),
        "repo_root": str(ROOT),
        "build_dir": str(build_dir),
        "profile": profile,
        "overall_status": overall_status,
        "release_ready": overall_status == "passed",
        "snapshot_sha256": snapshot_values[0] if len(snapshot_values) == 1 else None,
        "upstream_commit": upstream_values[0] if len(upstream_values) == 1 else None,
        "semantic_case_count": semantic_case_count,
        "tracked_regression_case_count": regression_case_count,
        "sections": sections,
        "missing_reports": missing_reports,
        "failed_reports": failed_reports,
        "consistency_errors": consistency_errors,
        "notes": notes,
    }
    return report


def _render_release_readiness_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# SP-DIFFER Release Readiness",
        "",
        "- generated_at: `{}`".format(report["generated_at"]),
        "- profile: `{}`".format(report["profile"]),
        "- overall_status: `{}`".format(report["overall_status"]),
        "- release_ready: `{}`".format("yes" if report["release_ready"] else "no"),
        "- upstream_commit: `{}`".format(report.get("upstream_commit") or "unknown"),
        "- snapshot_sha256: `{}`".format(report.get("snapshot_sha256") or "unknown"),
        "- semantic_case_count: `{}`".format(
            report["semantic_case_count"] if report["semantic_case_count"] is not None else "unknown"
        ),
        "- tracked_regression_case_count: `{}`".format(
            report["tracked_regression_case_count"]
            if report["tracked_regression_case_count"] is not None
            else "unknown"
        ),
        "",
    ]

    for section_name, section in report["sections"].items():
        lines.append("## {}".format(section_name.replace("_", " ").title()))
        lines.append("")
        for item in section["items"]:
            status = item["status"]
            suffix = ""
            if item.get("derived_case_count") is not None:
                suffix += " cases={}".format(item["derived_case_count"])
            if item.get("failure_count") is not None:
                suffix += " failures={}".format(item["failure_count"])
            elif item.get("failed_case_count") is not None:
                suffix += " failed={}".format(item["failed_case_count"])
            if item.get("seed") is not None:
                suffix += " seed={}".format(item["seed"])
            if item.get("iterations") is not None:
                suffix += " iterations={}".format(item["iterations"])
            if item.get("structured_iterations") is not None:
                suffix += " structured_iterations={}".format(item["structured_iterations"])
            if item.get("raw_iterations") is not None:
                suffix += " raw_iterations={}".format(item["raw_iterations"])
            if item.get("probe_status") is not None:
                suffix += " probe={}".format(item["probe_status"])
            if item.get("version_status") is not None:
                suffix += " version={}".format(item["version_status"])
            if item.get("local_pin") is not None:
                suffix += " local={}".format(item["local_pin"])
            if item.get("upstream_pin") is not None:
                suffix += " upstream={}".format(item["upstream_pin"])
            display_label = item.get("display_name") or item["label"]
            lines.append("- `{}`: `{}`{}".format(display_label, status, suffix))
            if item.get("failure_ids"):
                lines.append("  failure_ids: `{}`".format(", ".join(item["failure_ids"])))
            if item.get("summary"):
                lines.append("  summary: `{}`".format(item["summary"]))
        if section["missing_reports"]:
            lines.append("- missing: `{}`".format(", ".join(section["missing_reports"])))
        if section["failed_reports"]:
            lines.append("- failed: `{}`".format(", ".join(section["failed_reports"])))
        lines.append("")

    if report["consistency_errors"]:
        lines.append("## Consistency Errors")
        lines.append("")
        for error in report["consistency_errors"]:
            lines.append("- `{}`".format(error))
        lines.append("")

    if report["notes"]:
        lines.append("## Notes")
        lines.append("")
        for note in report["notes"]:
            lines.append("- {}".format(note))
        lines.append("")

    return "\n".join(lines)


def _print_release_readiness(report: Dict[str, Any]) -> None:
    print("SP-DIFFER release readiness")
    print("  status: {}".format(report["overall_status"]))
    print("  snapshot: {}".format(report.get("snapshot_sha256") or "unknown"))
    print("  upstream_commit: {}".format(report.get("upstream_commit") or "unknown"))
    print(
        "  semantic_case_count: {}".format(
            report["semantic_case_count"] if report["semantic_case_count"] is not None else "unknown"
        )
    )
    print(
        "  tracked_regression_case_count: {}".format(
            report["tracked_regression_case_count"]
            if report["tracked_regression_case_count"] is not None
            else "unknown"
        )
    )
    for section_name, section in report["sections"].items():
        passed = sum(1 for item in section["items"] if item["status"] == "passed")
        present = sum(1 for item in section["items"] if item["present"])
        print(
            "  {}: {}/{} passed".format(
                section_name, passed, section["expected_report_count"]
            )
        )
        if present != section["expected_report_count"]:
            print(
                "    missing: {}".format(", ".join(section["missing_reports"]))
            )
        if section["failed_reports"]:
            print("    failed: {}".format(", ".join(section["failed_reports"])))
    if report["consistency_errors"]:
        print("  consistency_errors:")
        for error in report["consistency_errors"]:
            print("    - {}".format(error))
    if report["notes"]:
        print("  notes:")
        for note in report["notes"]:
            print("    - {}".format(note))


def _write_report_outputs(
    report: Dict[str, Any],
    json_out: Optional[Path],
    markdown_out: Optional[Path],
) -> None:
    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if markdown_out is not None:
        markdown_out.parent.mkdir(parents=True, exist_ok=True)
        markdown_out.write_text(
            _render_release_readiness_markdown(report) + "\n", encoding="utf-8"
        )


def _run_command(command: Sequence[str], dry_run: bool = False) -> int:
    print("$ {}".format(shlex.join([str(part) for part in command])), flush=True)
    if dry_run:
        return 0
    proc = subprocess.run([str(part) for part in command], cwd=ROOT, check=False)
    return proc.returncode


def _verify_profile_commands(
    profile: str,
    make: str,
    python: str,
    seed: int,
    structured_iterations: int,
    raw_iterations: int,
) -> List[List[str]]:
    make_prefix = [make, "PYTHON={}".format(python)]
    commands = [
        make_prefix + ["check"],
        make_prefix + ["adapters"],
        make_prefix + ["regressions"],
    ]
    if profile == "release":
        commands.append(
            make_prefix
            + [
                "FUZZ_SEED={}".format(seed),
                "FUZZ_STRUCTURED_ITERATIONS={}".format(structured_iterations),
                "FUZZ_RAW_ITERATIONS={}".format(raw_iterations),
                "fuzz-semantic-workers",
            ]
        )
        commands.append(
            make_prefix
            + [
                "FUZZ_SEED={}".format(seed),
                "FUZZ_STRUCTURED_ITERATIONS={}".format(structured_iterations),
                "fuzz-semantic-adapters",
            ]
        )
    return commands


def _handle_status(args: argparse.Namespace) -> int:
    try:
        report = build_release_readiness_report(
            args.build_dir, args.regression_manifest, args.profile, args.external_probe
        )
    except Exception as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2
    _write_report_outputs(report, args.json_out, args.markdown_out)
    _print_release_readiness(report)
    if args.require_complete and report["missing_reports"]:
        return 2
    if args.require_green and report["overall_status"] != "passed":
        return 2
    return 0


def _handle_verify(args: argparse.Namespace) -> int:
    commands = _verify_profile_commands(
        args.profile,
        args.make,
        args.python,
        args.seed,
        args.structured_iterations,
        args.raw_iterations,
    )
    for command in commands:
        rc = _run_command(command, dry_run=args.dry_run)
        if rc != 0:
            return rc
    if args.refresh_external_probe:
        probe_json, probe_markdown = _resolve_external_probe_paths(
            args.build_dir, args.external_probe
        )
        if not args.external_probe_candidates.exists():
            if args.external_probe_candidates == DEFAULT_EXTERNAL_PROBE_CANDIDATES:
                print(
                    "note: external probe candidates file {} is absent; skipping live external probe refresh".format(
                        args.external_probe_candidates
                    )
                )
            else:
                print(
                    "error: external probe candidates file does not exist: {}".format(
                        args.external_probe_candidates
                    ),
                    file=sys.stderr,
                )
                return 2
        else:
            probe_command = _build_external_probe_command(
                args.python,
                args.external_probe_candidates,
                probe_json,
                probe_markdown,
            )
            rc = _run_command(probe_command, dry_run=args.dry_run)
            if rc != 0:
                return rc
    if args.skip_status or args.dry_run:
        if args.dry_run and not args.skip_status:
            print("dry-run complete; skipped release-readiness report generation")
        return 0
    report = build_release_readiness_report(
        args.build_dir, args.regression_manifest, args.profile, args.external_probe
    )
    _write_report_outputs(report, args.json_out, args.markdown_out)
    _print_release_readiness(report)
    if report["overall_status"] != "passed":
        return 2
    return 0


def _handle_replay(args: argparse.Namespace) -> int:
    target = args.path
    if target.is_file():
        artifact_dir = target.parent
    else:
        artifact_dir = target
    replay_script = artifact_dir / "replay.sh"
    summary_path = artifact_dir / "summary.json"

    if replay_script.exists():
        command = ["/bin/sh", str(replay_script)]
    elif summary_path.exists():
        summary = _read_json(summary_path)
        repro_cmd = summary.get("repro_cmd") or summary.get("replay_cmd")
        if not isinstance(repro_cmd, str) or not repro_cmd:
            raise SpDifferCliError("artifact summary is missing repro_cmd/replay_cmd")
        command = shlex.split(repro_cmd)
    else:
        raise SpDifferCliError(
            "{} does not contain replay.sh or summary.json".format(artifact_dir)
        )
    return _run_command(command, dry_run=args.dry_run)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Public CLI for SP-DIFFER workflows")
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify = subparsers.add_parser(
        "verify",
        help="Run a canonical verification suite and then summarize release readiness",
    )
    verify.add_argument(
        "--profile",
        choices=("quick", "release"),
        default="release",
        help="Verification profile to run",
    )
    verify.add_argument("--make", default=os.environ.get("MAKE", "make"), help="Make executable")
    verify.add_argument(
        "--python",
        default=sys.executable,
        help="Python interpreter passed through to make",
    )
    verify.add_argument("--seed", type=int, default=352, help="Deterministic fuzz seed")
    verify.add_argument(
        "--structured-iterations",
        type=int,
        default=64,
        help="Structured mutation count for release-profile fuzzing",
    )
    verify.add_argument(
        "--raw-iterations",
        type=int,
        default=64,
        help="Raw mutation count for release-profile fuzzing",
    )
    verify.add_argument(
        "--build-dir",
        type=Path,
        default=DEFAULT_BUILD_DIR,
        help="Build directory that holds reports",
    )
    verify.add_argument(
        "--external-probe",
        type=Path,
        help="Optional external-probe JSON to fold into release readiness; defaults to build/bip352_external_probe.json when present",
    )
    verify.add_argument(
        "--refresh-external-probe",
        action="store_true",
        help="Refresh live external BIP352 probe evidence before the final readiness verdict when candidate metadata is available",
    )
    verify.add_argument(
        "--external-probe-candidates",
        type=Path,
        default=DEFAULT_EXTERNAL_PROBE_CANDIDATES,
        help="Candidate metadata JSON used when refreshing the external probe",
    )
    verify.add_argument(
        "--regression-manifest",
        type=Path,
        default=DEFAULT_REGRESSION_MANIFEST,
        help="Tracked semantic regression manifest",
    )
    verify.add_argument(
        "--json-out",
        type=Path,
        default=DEFAULT_STATUS_JSON,
        help="Release-readiness JSON output path",
    )
    verify.add_argument(
        "--markdown-out",
        type=Path,
        default=DEFAULT_STATUS_MARKDOWN,
        help="Release-readiness markdown output path",
    )
    verify.add_argument(
        "--skip-status",
        action="store_true",
        help="Skip the final release-readiness report",
    )
    verify.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands without running them",
    )

    status = subparsers.add_parser(
        "status",
        help="Summarize current oracle/adapter/regression/fuzz evidence under build/",
    )
    status.add_argument(
        "--profile",
        choices=("quick", "release"),
        default="release",
        help="Evidence profile to require in the summary",
    )
    status.add_argument(
        "--build-dir",
        type=Path,
        default=DEFAULT_BUILD_DIR,
        help="Build directory that holds reports",
    )
    status.add_argument(
        "--external-probe",
        type=Path,
        help="Optional external-probe JSON to fold into release readiness; defaults to build/bip352_external_probe.json when present",
    )
    status.add_argument(
        "--regression-manifest",
        type=Path,
        default=DEFAULT_REGRESSION_MANIFEST,
        help="Tracked semantic regression manifest",
    )
    status.add_argument(
        "--json-out",
        type=Path,
        help="Optional JSON output path",
    )
    status.add_argument(
        "--markdown-out",
        type=Path,
        help="Optional markdown output path",
    )
    status.add_argument(
        "--require-complete",
        action="store_true",
        help="Exit non-zero if any expected report is missing",
    )
    status.add_argument(
        "--require-green",
        action="store_true",
        help="Exit non-zero unless the full release-readiness report is green",
    )

    replay = subparsers.add_parser(
        "replay",
        help="Replay a saved artifact directory that contains replay.sh or summary.json",
    )
    replay.add_argument("path", type=Path, help="Artifact directory or summary.json path")
    replay.add_argument(
        "--dry-run",
        action="store_true",
        help="Print replay command without running it",
    )

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            return _handle_verify(args)
        if args.command == "status":
            return _handle_status(args)
        if args.command == "replay":
            return _handle_replay(args)
        raise SpDifferCliError("unknown command: {}".format(args.command))
    except SpDifferCliError as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
