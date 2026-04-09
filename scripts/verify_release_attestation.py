#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify a packaged release archive against GitHub artifact attestations."""

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


DEFAULT_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
DEFAULT_RELEASE_WORKFLOW = ".github/workflows/release.yml"
REMOTE_NAME_CANDIDATES = ("public", "origin")


def _parse_repo_from_remote_url(url):
    match = re.search(r"github\.com[:/]([^/]+)/([^/.]+?)(?:\.git)?$", url.strip())
    if match is None:
        return None
    return "{}/{}".format(match.group(1), match.group(2))


def _infer_repo():
    for remote_name in REMOTE_NAME_CANDIDATES:
        result = subprocess.run(
            ["git", "config", "--get", "remote.{}.url".format(remote_name)],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            continue
        repo = _parse_repo_from_remote_url(result.stdout)
        if repo:
            return repo
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Verify a release archive using GitHub artifact attestations"
    )
    parser.add_argument("artifact", help="Path to the packaged release archive")
    parser.add_argument("--gh", default="gh", help="gh executable to use")
    parser.add_argument("--repo", help="Repository in owner/name form; defaults to the local git remote")
    parser.add_argument(
        "--signer-workflow",
        help="Expected signer workflow path in owner/name/.github/workflows/file.yml form",
    )
    parser.add_argument(
        "--source-ref",
        help="Expected git ref for the attestation source, for example refs/tags/v1.0.0",
    )
    args = parser.parse_args()

    if shutil.which(args.gh) is None:
        print("gh executable not found: {}".format(args.gh), file=sys.stderr)
        return 1

    artifact_path = Path(args.artifact)
    if not artifact_path.is_file():
        print("artifact not found: {}".format(artifact_path), file=sys.stderr)
        return 1

    repo = args.repo or _infer_repo()
    if not repo:
        print(
            "unable to infer GitHub repository from git remotes; pass --repo owner/name",
            file=sys.stderr,
        )
        return 1

    signer_workflow = args.signer_workflow or "{}/{}".format(repo, DEFAULT_RELEASE_WORKFLOW)
    command = [
        args.gh,
        "attestation",
        "verify",
        str(artifact_path),
        "--repo",
        repo,
        "--signer-workflow",
        signer_workflow,
        "--predicate-type",
        DEFAULT_PREDICATE_TYPE,
        "--deny-self-hosted-runners",
    ]
    if args.source_ref:
        command.extend(["--source-ref", args.source_ref])

    print("$ {}".format(" ".join(command)))
    return subprocess.run(command, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
