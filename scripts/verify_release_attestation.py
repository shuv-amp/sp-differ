#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify a packaged release archive against GitHub artifact attestations."""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path


DEFAULT_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
DEFAULT_RELEASE_WORKFLOW = ".github/workflows/release.yml"
REMOTE_NAME_CANDIDATES = ("public", "origin")
ARTIFACT_NAME_PATTERN = re.compile(r"^sp-differ-[A-Za-z0-9._-]+\.tar\.gz$")
REPO_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
WORKFLOW_PATTERN = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$"
)
SOURCE_REF_PATTERN = re.compile(r"^refs/(?:heads|tags)/[A-Za-z0-9._/-]+$")


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


def _resolve_artifact_path(raw_artifact):
    resolved = Path(os.path.realpath(raw_artifact))
    if not resolved.is_file():
        print("artifact not found: {}".format(resolved), file=sys.stderr)
        raise SystemExit(1)
    if resolved.name.startswith("-"):
        print("artifact name must not start with '-': {}".format(resolved.name), file=sys.stderr)
        raise SystemExit(1)
    if ARTIFACT_NAME_PATTERN.match(resolved.name) is None:
        print("unexpected artifact name: {}".format(resolved.name), file=sys.stderr)
        raise SystemExit(1)
    return resolved


def _validate_repo(repo):
    if REPO_PATTERN.match(repo) is None:
        print("invalid repository name: {}".format(repo), file=sys.stderr)
        raise SystemExit(1)
    return repo


def _validate_signer_workflow(signer_workflow):
    if WORKFLOW_PATTERN.match(signer_workflow) is None:
        print("invalid signer workflow: {}".format(signer_workflow), file=sys.stderr)
        raise SystemExit(1)
    return signer_workflow


def _validate_source_ref(source_ref):
    if SOURCE_REF_PATTERN.match(source_ref) is None:
        print("invalid source ref: {}".format(source_ref), file=sys.stderr)
        raise SystemExit(1)
    return source_ref


def main():
    parser = argparse.ArgumentParser(
        description="Verify a release archive using GitHub artifact attestations"
    )
    parser.add_argument("artifact", help="Path to the packaged release archive")
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

    artifact_path = _resolve_artifact_path(args.artifact)
    repo = args.repo or _infer_repo()
    if not repo:
        print(
            "unable to infer GitHub repository from git remotes; pass --repo owner/name",
            file=sys.stderr,
        )
        return 1
    repo = _validate_repo(repo)

    signer_workflow = args.signer_workflow or "{}/{}".format(repo, DEFAULT_RELEASE_WORKFLOW)
    signer_workflow = _validate_signer_workflow(signer_workflow)
    command = [
        "gh",
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
        command.extend(["--source-ref", _validate_source_ref(args.source_ref)])

    print("$ {}".format(" ".join(command)))
    return subprocess.run(command, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
