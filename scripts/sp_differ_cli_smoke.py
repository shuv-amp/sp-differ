#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Smoke tests for the public SP-DIFFER CLI/report aggregator."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import sp_differ_cli as cli  # noqa: E402


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _seed_report(name: str, snapshot: str, upstream: str, case_count: int = 55) -> dict:
    payload = {
        "status": "passed",
        "snapshot_sha256": snapshot,
        "upstream_commit": upstream,
        "derived_case_count": case_count,
    }
    if "fuzz" in name:
        payload.update(
            {
                "seed": 352,
                "structured_iterations": 64,
                "raw_iterations": 64,
                "failure_count": 0,
                "counts": {
                    "valid_baselines": 55,
                    "valid_mutations": 63,
                    "matched_reference_errors": 1,
                    "invalid_baselines": 8,
                    "invalid_mutations": 64,
                },
            }
        )
    elif "regressions" in name:
        payload.update(
            {
                "derived_case_count": 0,
                "passed_case_count": 0,
                "failed_case_count": 0,
            }
        )
    else:
        payload.update(
            {
                "passed_case_count": case_count,
                "failed_case_count": 0,
            }
        )
    return payload


def _current_external_probes() -> list[dict]:
    probes = []
    for candidate_id, name, local_pin, upstream_pin, probe_status in (
        ("spdk-rust", "SPDK adapter (silentpayments crate)", "0.5.0", "0.5.0", "metadata"),
        ("silent-payments", "silent-payments crate adapter", "0.1.1", "0.1.1", "metadata"),
        ("bip352", "bip352 crate adapter", "0.1.0-alpha.3", "0.1.0-alpha.3", "metadata"),
        ("go-bip352", "go-bip352 adapter", "v0.1.8", "v0.1.8", "metadata"),
        (
            "bdk-sp",
            "BDK bdk-sp",
            "2f28d19581202d46fd0b30c35b6ae1cc45e37ce5",
            "2f28d19581202d46fd0b30c35b6ae1cc45e37ce5",
            "passed",
        ),
    ):
        probes.append(
            {
                "candidate": candidate_id,
                "name": name,
                "integrated_in_repo": True,
                "status": probe_status,
                "summary": "local pin {} vs upstream {}".format(local_pin, upstream_pin),
                "version_status": "current",
                "local_version": local_pin if candidate_id != "bdk-sp" else None,
                "local_commit": local_pin if candidate_id == "bdk-sp" else None,
                "upstream_latest_version": upstream_pin if candidate_id != "bdk-sp" else None,
                "upstream_head": upstream_pin if candidate_id == "bdk-sp" else None,
            }
        )
    return probes


def _replay_custom_manifest_smoke(root: Path) -> None:
    tmp_root = root / "replay-smoke"
    artifact_root = tmp_root / "artifacts"
    manifest_path = tmp_root / "manifest.json"
    report_path = tmp_root / "report.json"

    case_path = ROOT / "tests" / "vectors" / "bip352" / "derived" / "v2" / "official_case_00_send_00.hex"
    expectation_path = (
        ROOT
        / "tests"
        / "vectors"
        / "bip352"
        / "derived"
        / "v2"
        / "official_case_00_send_00.expected.json"
    )
    official_manifest = ROOT / "tests" / "vectors" / "bip352" / "official" / "manifest.json"
    official_vectors = (
        ROOT / "tests" / "vectors" / "bip352" / "official" / "send_and_receive_test_vectors.json"
    )

    _write_json(
        manifest_path,
        {
            "cases": [
                {
                    "id": "custom_replay_case",
                    "kind": "send",
                    "path": str(case_path),
                    "expectation_path": str(expectation_path),
                }
            ]
        },
    )

    failing_adapter = "{} -c 'import sys; sys.exit(7)'".format(sys.executable)
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "run_semantic_adapter_cases.py"),
            "--adapter-name",
            "failing-adapter",
            "--adapter-cmd",
            failing_adapter,
            "--official-manifest",
            str(official_manifest),
            "--official-vectors",
            str(official_vectors),
            "--manifest",
            str(manifest_path),
            "--artifact-dir",
            str(artifact_root),
            "--json-out",
            str(report_path),
        ],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    _require(proc.returncode == 2, "expected failing adapter compare to fail")

    failure_dir = artifact_root / "custom_replay_case"
    summary = json.loads((failure_dir / "summary.json").read_text(encoding="utf-8"))
    repro_cmd = summary.get("repro_cmd", "")
    _require("--manifest" in repro_cmd, "expected replay command to preserve manifest path")
    _require(
        str(manifest_path) in repro_cmd,
        "expected replay command to include original manifest path",
    )

    replay_rc = cli.main(["replay", str(failure_dir)])
    _require(replay_rc == 2, "expected replay command to reach adapter failure")
    replay_report = json.loads((failure_dir / "replay_report.json").read_text(encoding="utf-8"))
    _require(
        replay_report["failed_case_count"] == 1,
        "expected replay report to capture the adapter failure",
    )
    _require(
        replay_report["failures"][0]["id"] == "custom_replay_case",
        "expected replay to preserve the custom case id",
    )


def _replay_adapter_fuzz_artifact_smoke(root: Path) -> None:
    tmp_root = root / "adapter-fuzz-replay-smoke"
    artifact_root = tmp_root / "artifacts"
    report_path = tmp_root / "report.json"

    failing_adapter = "{} -c 'import sys; sys.exit(7)'".format(sys.executable)
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "run_semantic_adapter_fuzz.py"),
            "--adapter-name",
            "failing-adapter",
            "--adapter-cmd",
            failing_adapter,
            "--iterations",
            "1",
            "--max-failures",
            "1",
            "--artifact-dir",
            str(artifact_root),
            "--json-out",
            str(report_path),
        ],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    _require(proc.returncode == 2, "expected adapter fuzz run to fail")

    failure_dir = artifact_root / "0000"
    summary = json.loads((failure_dir / "summary.json").read_text(encoding="utf-8"))
    repro_cmd = summary.get("repro_cmd", "")
    _require(repro_cmd, "expected adapter fuzz artifact repro_cmd")
    _require((failure_dir / "replay.sh").exists(), "expected adapter fuzz replay.sh")
    _require("--request-path" in repro_cmd, "expected exact request replay command")
    _require(
        str(failure_dir / "request.json") in repro_cmd,
        "expected replay command to point at saved request",
    )

    replay_rc = cli.main(["replay", str(failure_dir)])
    _require(replay_rc == 2, "expected adapter fuzz replay to preserve failure")
    replay_report = json.loads((failure_dir / "replay_report.json").read_text(encoding="utf-8"))
    _require(replay_report["status"] == "failed", "expected failing replay report")
    _require(
        replay_report["mode"] == "replay_request",
        "expected adapter fuzz replay report mode",
    )
    _require(replay_report["failure_count"] == 1, "expected exactly one replay failure")


def _replay_legacy_summary_cmd_smoke(root: Path) -> None:
    tmp_root = root / "legacy-replay-smoke"
    artifact_dir = tmp_root / "artifact"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    _write_json(
        artifact_dir / "summary.json",
        {
            "replay_cmd": "{} -c 'import sys; sys.exit(7)'".format(sys.executable),
        },
    )

    replay_rc = cli.main(["replay", str(artifact_dir)])
    _require(replay_rc == 7, "expected legacy replay_cmd fallback support")


def _external_probe_status_smoke(
    build_dir: Path,
    manifest: Path,
) -> None:
    probe_path = build_dir / "bip352_external_probe.json"
    current_probes = _current_external_probes()
    _write_json(
        probe_path,
        {
            "generated_at": "2026-04-01T00:00:00+00:00",
            "probes": current_probes,
        },
    )

    report = cli.build_release_readiness_report(build_dir, manifest)
    _require("external_probe" in report["sections"], "expected external probe section")
    _require(report["overall_status"] == "passed", "expected current external probe to stay green")
    external = report["sections"]["external_probe"]
    _require(
        external["expected_report_count"] == 5,
        "expected all integrated external probe candidates to be tracked",
    )
    _require(not external["missing_reports"], "expected no missing external probe candidates")

    stale_probe = {
        "generated_at": "2026-04-01T00:00:00+00:00",
        "probes": list(current_probes),
    }
    stale_probe["probes"][0] = dict(stale_probe["probes"][0])
    stale_probe["probes"][0]["version_status"] = "stale"
    stale_probe["probes"][0]["local_version"] = "0.4.0"
    stale_probe["probes"][0]["summary"] = "local crate pin 0.4.0 vs crates.io newest 0.5.0"
    _write_json(probe_path, stale_probe)

    failed = cli.build_release_readiness_report(build_dir, manifest)
    _require(failed["overall_status"] == "failed", "expected stale external probe to fail readiness")
    _require(
        "spdk-rust" in failed["failed_reports"],
        "expected stale external candidate to appear in failed reports",
    )

    rc = cli.main(
        [
            "status",
            "--build-dir",
            str(build_dir),
            "--regression-manifest",
            str(manifest),
            "--require-green",
        ]
    )
    _require(rc == 2, "expected status --require-green to fail on stale external probe")

    incomplete_probe = {
        "generated_at": "2026-04-01T00:00:00+00:00",
        "probes": current_probes[:4],
    }
    _write_json(probe_path, incomplete_probe)
    incomplete = cli.build_release_readiness_report(build_dir, manifest)
    _require(
        incomplete["overall_status"] == "incomplete",
        "expected partial external probe coverage to make readiness incomplete",
    )


def _verify_refresh_external_probe_smoke(build_dir: Path, manifest: Path) -> None:
    probe_path = build_dir / "verify_live_probe.json"
    probe_markdown = cli._external_probe_markdown_path(probe_path)
    report_json = build_dir / "verify_live_readiness.json"
    report_markdown = build_dir / "verify_live_readiness.md"
    probe_script = str(ROOT / "scripts" / "bip352_external_probe.py")
    original_run_command = cli._run_command

    def run_case(stale: bool) -> tuple[int, list[list[str]]]:
        recorded_commands: list[list[str]] = []

        def fake_run_command(command: list[str], dry_run: bool = False) -> int:
            stringified = [str(part) for part in command]
            recorded_commands.append(stringified)
            if len(stringified) >= 2 and stringified[1] == probe_script:
                probes = _current_external_probes()
                if stale:
                    probes[0] = dict(probes[0])
                    probes[0]["version_status"] = "stale"
                    probes[0]["local_version"] = "0.4.0"
                    probes[0]["summary"] = "local crate pin 0.4.0 vs crates.io newest 0.5.0"
                _write_json(
                    probe_path,
                    {
                        "generated_at": "2026-04-01T00:00:00+00:00",
                        "probes": probes,
                    },
                )
                probe_markdown.write_text("# synthetic probe\n", encoding="utf-8")
            return 0

        cli._run_command = fake_run_command
        try:
            rc = cli.main(
                [
                    "verify",
                    "--profile",
                    "release",
                    "--build-dir",
                    str(build_dir),
                    "--regression-manifest",
                    str(manifest),
                    "--json-out",
                    str(report_json),
                    "--markdown-out",
                    str(report_markdown),
                    "--external-probe",
                    str(probe_path),
                    "--refresh-external-probe",
                    "--python",
                    sys.executable,
                ]
            )
        finally:
            cli._run_command = original_run_command
        return rc, recorded_commands

    rc, recorded_commands = run_case(stale=False)
    _require(rc == 0, "expected refreshed current external probe verify to pass")
    report = json.loads(report_json.read_text(encoding="utf-8"))
    _require(report["overall_status"] == "passed", "expected refreshed verify report to pass")
    _require("external_probe" in report["sections"], "expected refreshed verify external probe section")
    probe_commands = [command for command in recorded_commands if len(command) >= 2 and command[1] == probe_script]
    _require(len(probe_commands) == 1, "expected exactly one external probe refresh command")
    _require(
        "--json-out" in probe_commands[0] and str(probe_path) in probe_commands[0],
        "expected refresh command to target the requested external probe JSON path",
    )
    _require(
        "--markdown-out" in probe_commands[0] and str(probe_markdown) in probe_commands[0],
        "expected refresh command to derive a matching external probe markdown path",
    )

    rc, _ = run_case(stale=True)
    _require(rc == 2, "expected refreshed stale external probe verify to fail")
    stale_report = json.loads(report_json.read_text(encoding="utf-8"))
    _require(stale_report["overall_status"] == "failed", "expected stale refreshed verify report")
    _require("spdk-rust" in stale_report["failed_reports"], "expected stale refreshed probe failure")


def main_smoke() -> int:
    snapshot = "5d43f942c8058f244d6422133dd6b078a5c21c3c702fa7a51b41b24c951709c9"
    upstream = "805c9b54f6d38f644d1f9c3ce871e2ea3df1f7d8"
    with tempfile.TemporaryDirectory(prefix="sp-differ-cli-smoke-") as tmpdir:
        root = Path(tmpdir)
        build_dir = root / "build"
        manifest = ROOT / "tests" / "regressions" / "semantic" / "manifest.json"
        expected_regression_case_count = cli._tracked_regression_case_count(manifest)

        for filename in (
            "bip352_v2_oracle_compare_report.json",
            "reference_semantic_adapter_report.json",
            "spdk_semantic_adapter_report.json",
            "spdk_semantic_worker_report.json",
            "silent_payments_semantic_adapter_report.json",
            "silent_payments_semantic_worker_report.json",
            "bip352_semantic_adapter_report.json",
            "bip352_semantic_worker_report.json",
            "go_bip352_semantic_adapter_report.json",
            "go_bip352_semantic_worker_report.json",
            "bdk_sp_semantic_adapter_report.json",
            "semantic_regressions_reference.json",
            "semantic_regressions_spdk_rust.json",
            "semantic_regressions_spdk_rust_ffi.json",
            "semantic_regressions_silent_payments.json",
            "semantic_regressions_silent_payments_ffi.json",
            "semantic_regressions_bip352.json",
            "semantic_regressions_bip352_ffi.json",
            "semantic_regressions_go_bip352.json",
            "semantic_regressions_go_bip352_ffi.json",
            "semantic_regressions_bdk_sp.json",
            "spdk_semantic_fuzz_report.json",
            "silent_payments_semantic_fuzz_report.json",
            "bip352_semantic_fuzz_report.json",
            "go_bip352_semantic_fuzz_report.json",
            "reference_semantic_adapter_fuzz_report.json",
            "spdk_semantic_adapter_fuzz_report.json",
            "silent_payments_semantic_adapter_fuzz_report.json",
            "bip352_semantic_adapter_fuzz_report.json",
            "go_bip352_semantic_adapter_fuzz_report.json",
            "bdk_sp_semantic_adapter_fuzz_report.json",
        ):
            _write_json(build_dir / filename, _seed_report(filename, snapshot, upstream))

        report = cli.build_release_readiness_report(build_dir, manifest)
        _require(report["overall_status"] == "passed", "expected passed readiness")
        _require(report["release_ready"], "expected release_ready")
        _require(report["semantic_case_count"] == 55, "expected semantic case count")
        _require(
            report["tracked_regression_case_count"] == expected_regression_case_count,
            "expected tracked regression manifest count",
        )

        json_out = build_dir / "readiness.json"
        markdown_out = build_dir / "readiness.md"
        rc = cli.main(
            [
                "status",
                "--build-dir",
                str(build_dir),
                "--regression-manifest",
                str(manifest),
                "--json-out",
                str(json_out),
                "--markdown-out",
                str(markdown_out),
                "--require-green",
            ]
        )
        _require(rc == 0, "expected status command success")
        _require(json_out.exists(), "expected JSON report output")
        _require(markdown_out.exists(), "expected markdown report output")

        _external_probe_status_smoke(build_dir, manifest)
        _verify_refresh_external_probe_smoke(build_dir, manifest)
        _replay_custom_manifest_smoke(root)
        _replay_adapter_fuzz_artifact_smoke(root)
        _replay_legacy_summary_cmd_smoke(root)

        (build_dir / "go_bip352_semantic_fuzz_report.json").unlink()
        incomplete = cli.build_release_readiness_report(build_dir, manifest)
        _require(incomplete["overall_status"] == "incomplete", "expected incomplete readiness")

    print("sp-differ CLI smoke OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main_smoke())
