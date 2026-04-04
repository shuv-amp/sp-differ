#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Smoke-test packaged release verification."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def _run(args, cwd):
    return subprocess.run(
        [sys.executable] + args,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )


def _make_cli_script(path: Path) -> None:
    path.write_text(
        "#!/bin/sh\n"
        "json_out=\"\"\n"
        "markdown_out=\"\"\n"
        "while [ \"$#\" -gt 0 ]; do\n"
        "  case \"$1\" in\n"
        "    --json-out) json_out=\"$2\"; shift 2 ;;\n"
        "    --markdown-out) markdown_out=\"$2\"; shift 2 ;;\n"
        "    --check-integrity) shift ;;\n"
        "    *) shift ;;\n"
        "  esac\n"
        "done\n"
        "printf '{\"passed\":true}\\n' > \"$json_out\"\n"
        "printf '# Integrity Check\\n' > \"$markdown_out\"\n"
        "printf 'OK: synthetic integrity check passed\\n'\n",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat_executable_bits())


def stat_executable_bits() -> int:
    return 0o755


def _write_checksums(package_dir: Path) -> None:
    lines = []
    for item in sorted(package_dir.iterdir()):
        if not item.is_file():
            continue
        if item.name in ("SHA256SUMS", "SHA256SUMS.asc"):
            continue
        if item.suffix in (".so", ".dylib", ".dll") or os.access(item, os.X_OK):
            lines.append("{}  {}".format(_sha256(item), item.name))
    (package_dir / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _make_gpg_home(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)


def _generate_test_key(gpg_home: Path) -> str:
    generated = subprocess.run(
        [
            "gpg",
            "--homedir",
            str(gpg_home),
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-generate-key",
            "SP-DIFFER Smoke Test Key <smoke@sp-differ.local>",
            "ed25519",
            "sign",
            "1d",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if generated.returncode != 0:
        raise SystemExit("failed to generate smoke-test gpg key:\n{}".format(generated.stdout + generated.stderr))
    listed = subprocess.run(
        ["gpg", "--homedir", str(gpg_home), "--list-secret-keys", "--with-colons"],
        check=True,
        capture_output=True,
        text=True,
    )
    for line in listed.stdout.splitlines():
        if line.startswith("fpr:"):
            return line.split(":")[9]
    raise SystemExit("failed to read smoke-test signing fingerprint")


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    script = repo_root / "scripts" / "verify_packaged_release.py"

    with tempfile.TemporaryDirectory(prefix="sp_differ_packaged_release_") as tmpdir:
        tmp = Path(tmpdir)
        package_dir = tmp / "sp-differ-v1.0.0-test-darwin-arm64"
        package_dir.mkdir()
        _make_cli_script(package_dir / "sp_differ_cli")
        for name in ("sp_differ_runner", "sp_differ_compare"):
            path = package_dir / name
            path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            path.chmod(path.stat().st_mode | stat_executable_bits())
        (package_dir / "libsp_differ_worker.dylib").write_bytes(b"synthetic-worker")
        _write_checksums(package_dir)

        archive_path = tmp / "release.tar.gz"
        with tarfile.open(archive_path, "w:gz") as archive:
            archive.add(package_dir, arcname=package_dir.name)

        passed = _run(
            [
                str(script),
                "--archive",
                str(archive_path),
                "--json-out",
                str(tmp / "ok.json"),
                "--markdown-out",
                str(tmp / "ok.md"),
            ],
            cwd=repo_root,
        )
        if passed.returncode != 0:
            raise SystemExit("expected packaged release verification to pass:\n{}".format(passed.stdout + passed.stderr))

        if shutil.which("gpg") is not None:
            keys_file = tmp / "KEYS"
            with tempfile.TemporaryDirectory(prefix="spg_") as gpg_tmpdir:
                gpg_home = Path(gpg_tmpdir)
                _make_gpg_home(gpg_home)
                fingerprint = _generate_test_key(gpg_home)
                exported = subprocess.run(
                    [
                        "gpg",
                        "--homedir",
                        str(gpg_home),
                        "--armor",
                        "--export",
                        fingerprint,
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                keys_file.write_text(exported.stdout, encoding="utf-8")
                signed = subprocess.run(
                    [
                        "gpg",
                        "--homedir",
                        str(gpg_home),
                        "--batch",
                        "--yes",
                        "--pinentry-mode",
                        "loopback",
                        "--armor",
                        "--local-user",
                        fingerprint,
                        "--output",
                        str(package_dir / "SHA256SUMS.asc"),
                        "--detach-sign",
                        str(package_dir / "SHA256SUMS"),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if signed.returncode != 0:
                    raise SystemExit("failed to sign smoke-test checksums:\n{}".format(signed.stdout + signed.stderr))
            with tarfile.open(archive_path, "w:gz") as archive:
                archive.add(package_dir, arcname=package_dir.name)
            signed_verify = _run(
                [
                    str(script),
                    "--archive",
                    str(archive_path),
                    "--require-signature",
                    "--keys-file",
                    str(keys_file),
                    "--json-out",
                    str(tmp / "signed.json"),
                    "--markdown-out",
                    str(tmp / "signed.md"),
                ],
                cwd=repo_root,
            )
            if signed_verify.returncode != 0:
                raise SystemExit("expected signed packaged release verification to pass:\n{}".format(signed_verify.stdout + signed_verify.stderr))
            signed_report = json.loads((tmp / "signed.json").read_text(encoding="utf-8"))
            if signed_report["signature"]["status"] != "verified":
                raise SystemExit("expected signature status to be verified")

        (package_dir / "sp_differ_compare").write_text("#!/bin/sh\necho drifted\n", encoding="utf-8")
        with tarfile.open(archive_path, "w:gz") as archive:
            archive.add(package_dir, arcname=package_dir.name)
        failed = _run(
            [
                str(script),
                "--archive",
                str(archive_path),
                "--json-out",
                str(tmp / "failed.json"),
                "--markdown-out",
                str(tmp / "failed.md"),
            ],
            cwd=repo_root,
        )
        if failed.returncode == 0:
            raise SystemExit("expected packaged release verification to fail after checksum drift")
        report = json.loads((tmp / "failed.json").read_text(encoding="utf-8"))
        if report["checksum_status"] != "failed":
            raise SystemExit("expected checksum status to fail after drift")

    print("packaged release verification smoke OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
