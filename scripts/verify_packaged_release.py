#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify a packaged release archive or extracted directory."""

import argparse
import hashlib
import os
import shutil
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from bip352_vectors import write_json


REPO_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_BASENAMES = ("sp_differ_cli", "sp_differ_runner", "sp_differ_compare")
LIBRARY_NAMES = (
    "libsp_differ_worker.so",
    "libsp_differ_worker.dylib",
    "sp_differ_worker.dll",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _resolve_package_root(extracted_root: Path) -> Path:
    entries = [
        entry
        for entry in extracted_root.iterdir()
        if entry.name != "__MACOSX" and not entry.name.startswith("._")
    ]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return extracted_root


def _list_package_binaries(package_root: Path) -> List[str]:
    binaries: List[str] = []
    for item in sorted(package_root.iterdir()):
        if not item.is_file():
            continue
        if item.name.startswith("._"):
            continue
        if item.name in ("SHA256SUMS", "SHA256SUMS.asc"):
            continue
        if item.name.endswith((".so", ".dylib", ".dll")) or item.stat().st_mode & 0o111:
            binaries.append(item.name)
    return binaries


def _parse_checksums(path: Path) -> Dict[str, str]:
    checksums: Dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split()
        if len(parts) != 2:
            raise RuntimeError("invalid checksum line: {}".format(line))
        checksum, name = parts
        if name in checksums:
            raise RuntimeError("duplicate checksum entry: {}".format(name))
        checksums[name] = checksum
    if not checksums:
        raise RuntimeError("checksum file is empty")
    return checksums


def _verify_signature(
    signature_path: Path, checksum_path: Path, keys_file: Optional[Path]
) -> Dict[str, Any]:
    if keys_file is not None and shutil.which("gpgv") is not None and shutil.which("gpg") is not None:
        with tempfile.TemporaryDirectory(prefix="sp_differ_verify_gpgv_") as tmpdir:
            tmp = Path(tmpdir)
            keyring = tmp / "trustedkeys.gpg"
            dearmor = subprocess.run(
                ["gpg", "--dearmor", "--output", str(keyring), str(keys_file)],
                check=False,
                capture_output=True,
                text=True,
            )
            detail_parts: List[str] = [(dearmor.stdout + dearmor.stderr).strip()]
            if dearmor.returncode != 0:
                detail = "\n".join(part for part in detail_parts if part)
                if len(detail) > 4000:
                    detail = detail[:4000] + "\n...[truncated]..."
                return {
                    "status": "failed",
                    "detail": detail,
                    "exit_code": dearmor.returncode,
                    "keys_file": str(keys_file),
                }
            completed = subprocess.run(
                [
                    "gpgv",
                    "--keyring",
                    str(keyring),
                    str(signature_path),
                    str(checksum_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            detail_parts.append((completed.stdout + completed.stderr).strip())
            detail = "\n".join(part for part in detail_parts if part)
            if len(detail) > 4000:
                detail = detail[:4000] + "\n...[truncated]..."
            return {
                "status": "verified" if completed.returncode == 0 else "failed",
                "detail": detail,
                "exit_code": completed.returncode,
                "keys_file": str(keys_file),
            }
    if shutil.which("gpg") is None:
        return {
            "status": "skipped",
            "detail": "gpg is not installed",
        }
    if keys_file is not None and not keys_file.is_file():
        return {
            "status": "failed",
            "detail": "keys file does not exist: {}".format(keys_file),
        }

    detail_parts: List[str] = []
    if keys_file is None:
        completed = subprocess.run(
            ["gpg", "--verify", str(signature_path), str(checksum_path)],
            check=False,
            capture_output=True,
            text=True,
        )
    else:
        with tempfile.TemporaryDirectory(prefix="sp_differ_verify_gpg_") as tmpdir:
            homedir = Path(tmpdir) / "gnupg"
            homedir.mkdir()
            os.chmod(homedir, 0o700)
            imported = subprocess.run(
                ["gpg", "--homedir", str(homedir), "--batch", "--import", str(keys_file)],
                check=False,
                capture_output=True,
                text=True,
            )
            detail_parts.append((imported.stdout + imported.stderr).strip())
            if imported.returncode != 0:
                detail = "\n".join(part for part in detail_parts if part)
                if len(detail) > 4000:
                    detail = detail[:4000] + "\n...[truncated]..."
                return {
                    "status": "failed",
                    "detail": detail,
                    "exit_code": imported.returncode,
                    "keys_file": str(keys_file),
                }
            completed = subprocess.run(
                [
                    "gpg",
                    "--homedir",
                    str(homedir),
                    "--batch",
                    "--verify",
                    str(signature_path),
                    str(checksum_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
    detail_parts.append((completed.stdout + completed.stderr).strip())
    detail = "\n".join(part for part in detail_parts if part)
    if len(detail) > 4000:
        detail = detail[:4000] + "\n...[truncated]..."
    return {
        "status": "verified" if completed.returncode == 0 else "failed",
        "detail": detail,
        "exit_code": completed.returncode,
        "keys_file": None if keys_file is None else str(keys_file),
    }


def _run_integrity_check(package_root: Path, cli_path: Path) -> Dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="sp_differ_pkg_integrity_") as tmpdir:
        tmp = Path(tmpdir)
        json_out = tmp / "integrity.json"
        markdown_out = tmp / "integrity.md"
        completed = subprocess.run(
            [
                str(cli_path),
                "--check-integrity",
                "--json-out",
                str(json_out),
                "--markdown-out",
                str(markdown_out),
            ],
            cwd=package_root,
            check=False,
            capture_output=True,
            text=True,
        )
        detail = (completed.stdout + completed.stderr).strip()
        if len(detail) > 4000:
            detail = detail[:4000] + "\n...[truncated]..."
        return {
            "status": "passed" if completed.returncode == 0 else "failed",
            "detail": detail,
            "exit_code": completed.returncode,
            "json_out": str(json_out),
            "markdown_out": str(markdown_out),
        }


def _render_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Packaged Release Verification",
        "",
        "- generated_at_utc: `{}`".format(report["generated_at_utc"]),
        "- status: `{}`".format(report["status"]),
        "- package_root: `{}`".format(report["package_root"]),
        "- source: `{}`".format(report["source"]),
        "",
        "## Checks",
        "",
        "- expected binaries present: `{}`".format(report["expected_binaries_present"]),
        "- checksum status: `{}`".format(report["checksum_status"]),
        "- checksum file status: `{}`".format(report["checksum_file_status"]),
        "- self-check status: `{}`".format(report["integrity_check"]["status"]),
        "- signature status: `{}`".format(report["signature"]["status"]),
        "",
    ]

    if report["missing_items"]:
        lines.extend(["## Missing", ""])
        for item in report["missing_items"]:
            lines.append("- `{}`".format(item))
        lines.append("")

    if report["checksum_mismatches"]:
        lines.extend(["## Checksum Mismatches", ""])
        for item in report["checksum_mismatches"]:
            lines.append(
                "- `{}` expected `{}` actual `{}`".format(
                    item["path"], item["expected_sha256"], item["actual_sha256"]
                )
            )
        lines.append("")

    return "\n".join(lines)


def _load_package(source_archive: Optional[Path], source_dir: Optional[Path]) -> Tuple[Path, Path, tempfile.TemporaryDirectory]:
    if source_archive is not None:
        if not source_archive.is_file():
            raise RuntimeError("archive does not exist: {}".format(source_archive))
        tmpdir = tempfile.TemporaryDirectory(prefix="sp_differ_packaged_release_")
        tmp = Path(tmpdir.name)
        with tarfile.open(source_archive, "r:*") as archive:
            archive.extractall(tmp)
        return _resolve_package_root(tmp), source_archive, tmpdir
    if source_dir is not None:
        if not source_dir.is_dir():
            raise RuntimeError("directory does not exist: {}".format(source_dir))
        tmpdir = tempfile.TemporaryDirectory(prefix="sp_differ_packaged_release_dir_")
        return source_dir.resolve(), source_dir.resolve(), tmpdir
    raise RuntimeError("either --archive or --directory is required")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a packaged release archive or directory")
    parser.add_argument("--archive", type=Path, help="Packaged release tarball to verify")
    parser.add_argument("--directory", type=Path, help="Extracted release directory to verify")
    parser.add_argument(
        "--json-out",
        type=Path,
        default=Path("build/packaged_release_verification.json"),
        help="Where to write the machine-readable report",
    )
    parser.add_argument(
        "--markdown-out",
        type=Path,
        default=Path("build/packaged_release_verification.md"),
        help="Where to write the markdown report",
    )
    parser.add_argument(
        "--require-signature",
        action="store_true",
        help="Fail if SHA256SUMS.asc is missing or does not verify",
    )
    parser.add_argument(
        "--keys-file",
        type=Path,
        help="Optional ASCII-armored public key bundle used to verify signatures",
    )
    args = parser.parse_args()

    if bool(args.archive) == bool(args.directory):
        raise RuntimeError("exactly one of --archive or --directory must be provided")

    package_root, source, temp_context = _load_package(args.archive, args.directory)
    try:
        missing_items: List[str] = []
        checksum_mismatches: List[Dict[str, str]] = []
        package_binaries = _list_package_binaries(package_root)

        for name in EXPECTED_BASENAMES:
            if not (package_root / name).is_file():
                missing_items.append(name)
        if not any((package_root / name).is_file() for name in LIBRARY_NAMES):
            missing_items.append("libsp_differ_worker.(so|dylib|dll)")

        checksum_path = package_root / "SHA256SUMS"
        checksum_file_status = "passed"
        checksum_status = "passed"
        checksums: Dict[str, str] = {}
        if not checksum_path.is_file():
            checksum_file_status = "failed"
            checksum_status = "failed"
            missing_items.append("SHA256SUMS")
        else:
            checksums = _parse_checksums(checksum_path)
            for name, expected_sha in checksums.items():
                target = package_root / name
                if not target.is_file():
                    missing_items.append(name)
                    checksum_status = "failed"
                    continue
                actual_sha = _sha256(target)
                if actual_sha != expected_sha:
                    checksum_status = "failed"
                    checksum_mismatches.append(
                        {
                            "path": name,
                            "expected_sha256": expected_sha,
                            "actual_sha256": actual_sha,
                        }
                    )
            unexpected = sorted(set(package_binaries) - set(checksums.keys()))
            if unexpected:
                checksum_status = "failed"
                for name in unexpected:
                    missing_items.append("checksum missing for {}".format(name))

        keys_file = args.keys_file
        if keys_file is None:
            default_keys = REPO_ROOT / "KEYS"
            if default_keys.is_file():
                keys_file = default_keys

        signature_path = package_root / "SHA256SUMS.asc"
        if signature_path.is_file():
            signature = _verify_signature(signature_path, checksum_path, keys_file)
        elif args.require_signature:
            signature = {
                "status": "failed",
                "detail": "SHA256SUMS.asc is missing",
                "keys_file": None if keys_file is None else str(keys_file),
            }
            missing_items.append("SHA256SUMS.asc")
        else:
            signature = {
                "status": "missing",
                "detail": "SHA256SUMS.asc is not present",
                "keys_file": None if keys_file is None else str(keys_file),
            }

        cli_path = package_root / "sp_differ_cli"
        if cli_path.is_file():
            integrity_check = _run_integrity_check(package_root, cli_path)
        else:
            integrity_check = {
                "status": "failed",
                "detail": "sp_differ_cli is missing",
                "exit_code": 127,
            }

        expected_binaries_present = not any(
            item in EXPECTED_BASENAMES or item == "libsp_differ_worker.(so|dylib|dll)"
            for item in missing_items
        )
        status = "passed"
        if not expected_binaries_present:
            status = "failed"
        if checksum_file_status != "passed" or checksum_status != "passed":
            status = "failed"
        if integrity_check["status"] != "passed":
            status = "failed"
        if args.require_signature and signature["status"] != "verified":
            status = "failed"
        if signature["status"] == "failed":
            status = "failed"

        report: Dict[str, Any] = {
            "packaged_release_verification_version": 1,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "status": status,
            "package_root": str(package_root),
            "source": str(source),
            "expected_binaries_present": expected_binaries_present,
            "checksum_file_status": checksum_file_status,
            "checksum_status": checksum_status,
            "signature": signature,
            "integrity_check": integrity_check,
            "missing_items": sorted(dict.fromkeys(missing_items)),
            "checksum_mismatches": checksum_mismatches,
            "package_binaries": package_binaries,
        }

        write_json(args.json_out, report)
        args.markdown_out.write_text(_render_markdown(report) + "\n", encoding="utf-8")

        print("packaged release verification {}".format(status))
        print("  package root: {}".format(package_root))
        print("  checksum status: {}".format(checksum_status))
        print("  self-check: {}".format(integrity_check["status"]))
        print("  signature: {}".format(signature["status"]))
        return 0 if status == "passed" else 1
    finally:
        temp_context.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
