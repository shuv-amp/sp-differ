#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run external BIP352 candidate probes and persist machine-readable evidence."""

import argparse
import json
import re
import shutil
import subprocess
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CANDIDATES = ROOT / "research" / "bip352_candidates.json"


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _base_probe(candidate: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "candidate": candidate.get("id"),
        "name": candidate.get("name"),
        "integrated_in_repo": bool(candidate.get("integrated_in_repo")),
        "repo_adapter_name": candidate.get("repo_adapter_name"),
    }


def _run(command: List[str], cwd: Path) -> Dict[str, Any]:
    proc = subprocess.run(
        command,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    return {
        "command": command,
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def _http_json(url: str) -> Dict[str, Any]:
    request = urllib.request.Request(url, headers={"User-Agent": "sp-differ-external-probe"})
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def _http_text(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "sp-differ-external-probe"})
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.read().decode("utf-8")


def _normalize_version(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    normalized = value.strip()
    if normalized.startswith("v"):
        normalized = normalized[1:]
    return normalized or None


def _extract_cargo_dependency_version(manifest_path: Path, dependency_name: str) -> Optional[str]:
    pattern = re.compile(
        r'^\s*{}\s*=\s*(?:"([^"]+)"|\{{[^}}]*\bversion\s*=\s*"([^"]+)"[^}}]*\}})\s*$'.format(
            re.escape(dependency_name)
        ),
        re.MULTILINE,
    )
    match = pattern.search(manifest_path.read_text(encoding="utf-8"))
    if match is None:
        return None
    return match.group(1) or match.group(2)


def _extract_cargo_package_name(manifest_path: Path) -> Optional[str]:
    manifest = manifest_path.read_text(encoding="utf-8")
    package_section = re.search(
        r"^\[package\]\n(?P<body>.*?)(?=^\[|\Z)",
        manifest,
        re.MULTILINE | re.DOTALL,
    )
    if package_section is None:
        return None
    match = re.search(r'^name = "([^"]+)"$', package_section.group("body"), re.MULTILINE)
    if match is None:
        return None
    return match.group(1)


def _extract_go_module_version(manifest_path: Path, module_name: str) -> Optional[str]:
    pattern = re.compile(
        r'^\s*{}\s+(v[^\s]+)\s*$'.format(re.escape(module_name)),
        re.MULTILINE,
    )
    match = pattern.search(manifest_path.read_text(encoding="utf-8"))
    if match is None:
        return None
    return match.group(1)


def _parse_cargo_lock_packages(lock_path: Path) -> List[Dict[str, Any]]:
    text = lock_path.read_text(encoding="utf-8")
    package_pattern = re.compile(
        r'\[\[package\]\]\n(?P<body>.*?)(?=\n\[\[package\]\]|\Z)',
        re.DOTALL,
    )
    packages: List[Dict[str, Any]] = []
    for match in package_pattern.finditer(text):
        body = match.group("body")
        name_match = re.search(r'^name = "([^"]+)"$', body, re.MULTILINE)
        version_match = re.search(r'^version = "([^"]+)"$', body, re.MULTILINE)
        if name_match is None or version_match is None:
            continue

        dependencies: List[str] = []
        dependencies_match = re.search(
            r"^dependencies = \[\n(?P<body>.*?)\n\]$",
            body,
            re.MULTILINE | re.DOTALL,
        )
        if dependencies_match is not None:
            for line in dependencies_match.group("body").splitlines():
                dep_match = re.match(r'^\s*"([^"]+)"\s*,?\s*$', line)
                if dep_match is not None:
                    dependencies.append(dep_match.group(1))

        source_match = re.search(r'^source = "([^"]+)"$', body, re.MULTILINE)
        packages.append(
            {
                "name": name_match.group(1),
                "version": version_match.group(1),
                "source": source_match.group(1) if source_match is not None else None,
                "dependencies": dependencies,
            }
        )
    return packages


def _parse_cargo_lock_dependency_entry(entry: str) -> tuple[str, Optional[str]]:
    cleaned = entry.strip()
    if cleaned.endswith(")") and " (" in cleaned:
        cleaned = cleaned.rsplit(" (", 1)[0]
    if " " not in cleaned:
        return cleaned, None
    package_name, candidate_version = cleaned.rsplit(" ", 1)
    if re.match(r"^[0-9A-Za-z.+-]+$", candidate_version):
        return package_name, candidate_version
    return cleaned, None


def _extract_cargo_lock_dependency_version(
    lock_path: Path,
    root_package_name: Optional[str],
    dependency_name: str,
) -> Optional[str]:
    if root_package_name is None:
        return None

    packages = _parse_cargo_lock_packages(lock_path)
    root_package = None
    for package in packages:
        if package["name"] == root_package_name and package["source"] is None:
            root_package = package
            break
    if root_package is None:
        return None

    direct_dependency_found = False
    for dependency_entry in root_package["dependencies"]:
        package_name, package_version = _parse_cargo_lock_dependency_entry(dependency_entry)
        if package_name != dependency_name:
            continue
        direct_dependency_found = True
        if package_version is not None:
            return package_version
        break
    if not direct_dependency_found:
        return None

    matching_versions = sorted(
        {package["version"] for package in packages if package["name"] == dependency_name}
    )
    if len(matching_versions) == 1:
        return matching_versions[0]
    return None


def _extract_cargo_lock_git_commit(lock_path: Path, package_name: str) -> Optional[str]:
    for package in _parse_cargo_lock_packages(lock_path):
        if package["name"] != package_name:
            continue
        source = package.get("source")
        if source is None:
            continue
        source_match = re.match(r"git\+[^#]+#([0-9a-f]+)$", source)
        if source_match is not None:
            return source_match.group(1)
    return None


def _git_ls_remote_head(repo_url: str) -> Optional[str]:
    proc = subprocess.run(
        ["git", "ls-remote", repo_url, "HEAD"],
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    if proc.returncode != 0:
        return None
    fields = proc.stdout.strip().split()
    if not fields:
        return None
    return fields[0]


def _probe_crate(candidate: Dict[str, Any], tracking: Dict[str, Any]) -> Dict[str, Any]:
    crate_name = tracking["crate"]
    manifest_path = ROOT / tracking["local_manifest"]
    dependency_name = tracking["local_dependency"]
    lock_path = ROOT / tracking.get("local_lock", manifest_path.with_name("Cargo.lock"))
    root_package_name = tracking.get("local_root_package") or _extract_cargo_package_name(
        manifest_path
    )
    local_version = None
    local_pin_source = None
    if lock_path.exists():
        local_version = _extract_cargo_lock_dependency_version(
            lock_path,
            root_package_name,
            dependency_name,
        )
        if local_version is not None:
            local_pin_source = "Cargo.lock"
    if local_version is None:
        local_version = _extract_cargo_dependency_version(manifest_path, dependency_name)
        if local_version is not None:
            local_pin_source = "Cargo.toml"

    upstream = _http_json("https://crates.io/api/v1/crates/{}".format(crate_name))
    crate = upstream["crate"]
    latest_version = crate["newest_version"]
    version_status = (
        "current"
        if _normalize_version(local_version) == _normalize_version(latest_version)
        else "stale"
    )
    result = _base_probe(candidate)
    result.update(
        {
            "status": "metadata",
            "summary": "local {} crate pin {} vs crates.io newest {}".format(
                "resolved" if local_pin_source == "Cargo.lock" else "manifest",
                local_version or "unknown",
                latest_version,
            ),
            "local_version": local_version,
            "local_pin_source": local_pin_source,
            "upstream_latest_version": latest_version,
            "upstream_updated_at": crate.get("updated_at"),
            "upstream_repository": crate.get("repository"),
            "version_status": version_status,
            "version_source": "crates.io",
        }
    )
    return result


def _probe_go_module(candidate: Dict[str, Any], tracking: Dict[str, Any]) -> Dict[str, Any]:
    module_name = tracking["module"]
    manifest_path = ROOT / tracking["local_manifest"]
    local_version = _extract_go_module_version(manifest_path, module_name)
    upstream = json.loads(
        _http_text("https://proxy.golang.org/{}/@latest".format(module_name))
    )
    latest_version = upstream["Version"]
    version_status = (
        "current"
        if _normalize_version(local_version) == _normalize_version(latest_version)
        else "stale"
    )
    result = _base_probe(candidate)
    result.update(
        {
            "status": "metadata",
            "summary": "local module pin {} vs Go proxy latest {}".format(
                local_version or "unknown", latest_version
            ),
            "local_version": local_version,
            "upstream_latest_version": latest_version,
            "upstream_updated_at": upstream.get("Time"),
            "upstream_commit": upstream.get("Origin", {}).get("Hash"),
            "version_status": version_status,
            "version_source": "proxy.golang.org",
        }
    )
    return result


def _probe_bdk_sp(candidate: Dict[str, Any], tracking: Dict[str, Any]) -> Dict[str, Any]:
    repo_url = tracking["repo"]
    local_commit = _extract_cargo_lock_git_commit(ROOT / tracking["local_lock"], tracking["local_package"])
    upstream_head = _git_ls_remote_head(repo_url)
    version_status = "unknown"
    if local_commit is not None and upstream_head is not None:
        version_status = "current" if local_commit == upstream_head else "stale"

    result: Dict[str, Any] = _base_probe(candidate)
    result.update(
        {
            "repo_url": repo_url,
            "local_commit": local_commit,
            "upstream_head": upstream_head,
            "version_status": version_status,
            "version_source": "git ls-remote",
        }
    )

    with tempfile.TemporaryDirectory(prefix="sp_differ_probe_bdksp_") as tmp:
        tmp_path = Path(tmp)
        root = tmp_path / "repo"
        clone = _run(["git", "clone", "--depth", "1", repo_url, str(root)], tmp_path)
        result["clone"] = clone
        if clone["exit_code"] != 0:
            result["status"] = "failed"
            result["summary"] = "clone failed"
            return result

        cargo = shutil.which("cargo") or str(Path.home() / ".cargo" / "bin" / "cargo")
        lib_tests = _run([cargo, "test", "-p", "bdk_sp", "--lib", "--quiet"], root)
        full_tests = _run([cargo, "test", "-p", "bdk_sp", "--quiet"], root)
        head_commit = _run(["git", "rev-parse", "HEAD"], root)
        head_timestamp = _run(["git", "log", "-1", "--format=%cI"], root)

        summary_parts = [
            "local commit {} vs upstream HEAD {}".format(
                local_commit or "unknown", upstream_head or "unknown"
            )
        ]
        if lib_tests["exit_code"] == 0:
            summary_parts.append("library tests passed")
        else:
            summary_parts.append("library tests failed")

        if full_tests["exit_code"] == 0:
            summary_parts.append("full package tests passed")
        else:
            if "Bad CPU type in executable" in (full_tests["stderr"] + full_tests["stdout"]):
                summary_parts.append("integration tests blocked by host bitcoind binary architecture")
            else:
                summary_parts.append("full package tests failed")

        result.update(
            {
                "status": "passed" if lib_tests["exit_code"] == 0 else "failed",
                "summary": "; ".join(summary_parts),
                "lib_tests": lib_tests,
                "full_tests": full_tests,
                "cloned_head": head_commit["stdout"].strip() or None,
                "cloned_head_time": head_timestamp["stdout"].strip() or None,
            }
        )
        return result


def _probe_candidate(candidate: Dict[str, Any]) -> Dict[str, Any]:
    try:
        tracking = candidate.get("version_tracking")
        if not isinstance(tracking, dict):
            return {
                **_base_probe(candidate),
                "status": "skipped",
                "summary": "no version tracking metadata",
            }

        kind = tracking.get("kind")
        if kind == "crate":
            return _probe_crate(candidate, tracking)
        if kind == "go-module":
            return _probe_go_module(candidate, tracking)
        if kind == "git-head":
            return _probe_bdk_sp(candidate, tracking)
        return {
            **_base_probe(candidate),
            "status": "skipped",
            "summary": "unsupported version tracking kind: {}".format(kind),
        }
    except Exception as exc:
        return {
            **_base_probe(candidate),
            "status": "failed",
            "summary": "probe failed: {}".format(exc),
            "version_status": "unknown",
        }


def _render_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# External BIP352 Candidate Probe",
        "",
        "- generated_at: `{}`".format(report["generated_at"]),
        "- candidates_file: `{}`".format(report["inputs"]["candidates"]),
        "",
    ]
    for probe in report.get("probes", []):
        lines.append("## {}".format(probe.get("candidate")))
        lines.append("")
        lines.append("- status: `{}`".format(probe.get("status")))
        lines.append("- summary: `{}`".format(probe.get("summary")))
        if probe.get("version_status"):
            lines.append("- version_status: `{}`".format(probe.get("version_status")))
        if probe.get("local_version") or probe.get("local_commit"):
            lines.append(
                "- local_pin: `{}`".format(
                    probe.get("local_version") or probe.get("local_commit")
                )
            )
        if probe.get("local_pin_source"):
            lines.append("- local_pin_source: `{}`".format(probe.get("local_pin_source")))
        if probe.get("upstream_latest_version") or probe.get("upstream_head"):
            lines.append(
                "- upstream_latest: `{}`".format(
                    probe.get("upstream_latest_version") or probe.get("upstream_head")
                )
            )
        if probe.get("upstream_updated_at") or probe.get("cloned_head_time"):
            lines.append(
                "- upstream_timestamp: `{}`".format(
                    probe.get("upstream_updated_at") or probe.get("cloned_head_time")
                )
            )
        if probe.get("repo_url"):
            lines.append("- repo: `{}`".format(probe.get("repo_url")))
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe external BIP352 candidate repositories")
    parser.add_argument(
        "--candidates",
        type=Path,
        default=DEFAULT_CANDIDATES,
        help="Candidate metadata JSON path",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=Path("build/bip352_external_probe.json"),
        help="Machine-readable probe output path",
    )
    parser.add_argument(
        "--markdown-out",
        type=Path,
        default=Path("build/bip352_external_probe.md"),
        help="Markdown probe output path",
    )
    args = parser.parse_args()

    candidates_doc = _load_json(args.candidates)
    candidates = candidates_doc.get("candidates", [])
    if not isinstance(candidates, list) or not candidates:
        raise SystemExit("error: candidate list is empty")

    probes = [_probe_candidate(candidate) for candidate in candidates]
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "candidates": str(args.candidates),
        },
        "probes": probes,
    }

    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.markdown_out.write_text(_render_markdown(report) + "\n", encoding="utf-8")

    print("bip352 external probe complete")
    print("  json: {}".format(args.json_out))
    print("  markdown: {}".format(args.markdown_out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
