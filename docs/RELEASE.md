# Release Process

This project should not ship public releases with vague "green locally" claims.

Every release candidate should be backed by:

1. a refreshed live readiness report
2. a benchmark summary from the current harness matrix
3. a hashed release-evidence manifest that records the exact supporting files
4. a passing release-evidence verification report generated from that manifest
5. an annotated, GPG-signed tag from a maintainer whose fingerprint is published in `../SECURITY.md`
6. a passing compiled self-check from `sp_differ_cli --check-integrity`
7. signed `SHA256SUMS` for the packaged binaries

## Required Commands

The strongest integrated local lane is:

```bash
make maturity-signoff
```

For release binaries specifically:

```bash
make release-prereqs
make release SP_DIFFER_BUILD_VERSION=v1.0.0
./build/release/sp_differ_cli --check-integrity --json-out build/release_check_integrity.json --markdown-out build/release_check_integrity.md
make package-release SP_DIFFER_BUILD_VERSION=v1.0.0
make verify-packaged-release SP_DIFFER_BUILD_VERSION=v1.0.0
./scripts/sign_release.sh --input-dir build/release --output-dir build/release --gpg-key <fingerprint>
```

That runs:

- `make verify-release-live`
- `make bench-adapters`
- `make release-report`
- `make release-evidence`
- `make verify-release-evidence`

Key outputs:

- release prereq JSON and Markdown reports under `build/`
- live release-readiness JSON and Markdown reports under `build/`
- benchmark summary JSON and Markdown reports under `build/`
- release-evidence manifest JSON and Markdown reports under `build/`
- release-evidence verification JSON and Markdown reports under `build/`
- packaged-release verification JSON and Markdown reports under `build/`

To re-check the evidence manifest later:

```bash
make verify-release-evidence
```

To verify the packaged tarball as a consumer would see it:

```bash
make verify-packaged-release SP_DIFFER_BUILD_VERSION=v1.0.0
```

For the strict public-release gate, which also requires a signed checksum file:

```bash
make official-release-ready SP_DIFFER_BUILD_VERSION=v1.0.0 RELEASE_SIGN_GPG_KEY=<fingerprint>
```

## Tagging Standard

Public releases should use annotated signed tags, for example:

```bash
git tag -s v0.1.0 -m "SP-DIFFER v0.1.0"
git tag -v v0.1.0
```

If maintainer fingerprints are not yet published in `../SECURITY.md`, stop there and publish them before advertising the release as a verified signed release.

The repository also carries `.github/workflows/release.yml`, which is the tag-triggered packaging lane. It is intentionally gated on the existing compiled smoke path and the native/reference fuzz lane before it uploads Linux x64, Linux arm64, and macOS universal artifacts.

## What To Publish

Each release should publish:

- the signed tag
- the compiled integrity report from `sp_differ_cli --check-integrity`
- `SHA256SUMS` and its detached GPG signature
- the readiness reports
- the benchmark summary
- the release-evidence manifest
- any CI artifact tarballs associated with the release candidate

## Review Bar

Before release:

- confirm the live release report is green
- confirm benchmark reports are directly comparable and labeled as harness measurements
- confirm the release-evidence manifest hashes the exact files being published
- confirm `build/release_evidence_verification.json` is still `passed` at the moment you package the release
- confirm the signed tag verifies against the maintainer key you expect
- confirm any remaining caveats are written down plainly
