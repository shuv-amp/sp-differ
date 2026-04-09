#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Smoke-test the release attestation wrapper with a fake gh executable."""

import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RUNNER = ROOT / "scripts" / "verify_release_attestation.py"


def main():
    with tempfile.TemporaryDirectory(prefix="sp_differ_release_attestation_") as temp_dir:
        root = Path(temp_dir)
        fake_gh = root / "gh"
        log_path = root / "gh.log"
        artifact_path = root / "sp-differ-v1.0.0-linux-x64.tar.gz"
        artifact_path.write_bytes(b"test-archive")

        fake_gh.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' \"$@\" > \"$SP_DIFFER_GH_LOG\"\n",
            encoding="utf-8",
        )
        fake_gh.chmod(fake_gh.stat().st_mode | stat.S_IXUSR)

        env = dict(os.environ)
        env["SP_DIFFER_GH_LOG"] = str(log_path)
        env["PATH"] = "{}:{}".format(root, env.get("PATH", ""))
        result = subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                str(artifact_path),
                "--repo",
                "shuv-amp/sp-differ",
                "--source-ref",
                "refs/tags/v1.0.0",
            ],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
        if result.returncode != 0:
            print(result.stdout, end="")
            print(result.stderr, end="", file=sys.stderr)
            raise SystemExit("verify_release_attestation.py smoke unexpectedly failed")

        logged_args = log_path.read_text(encoding="utf-8").splitlines()
        expected = [
            "attestation",
            "verify",
            str(artifact_path.resolve()),
            "--repo",
            "shuv-amp/sp-differ",
            "--signer-workflow",
            "shuv-amp/sp-differ/.github/workflows/release.yml",
            "--predicate-type",
            "https://slsa.dev/provenance/v1",
            "--deny-self-hosted-runners",
            "--source-ref",
            "refs/tags/v1.0.0",
        ]
        if logged_args != expected:
            raise SystemExit("unexpected gh attestation arguments: {}".format(logged_args))

    print("release attestation smoke OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
