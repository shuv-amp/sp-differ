# Security Policy

SP-DIFFER is a testing framework. It does not hold production keys and should not be used as a wallet.

## Reporting a Vulnerability

If you discover a security issue in this repository:
- Open a GitHub issue in this repository and mark it security-sensitive.
- If GitHub private security advisories are available for the repository, prefer that path for issues that should not be disclosed publicly before a fix is ready.
- No separate private email or other private reporting channel is documented for this repository today.

Maintainers should acknowledge the report in the issue or advisory and coordinate follow-up there.

## Release Verification

Public releases should use annotated GPG-signed tags.

Published release-signing fingerprint for the current repo-local signing workflow:

- `3537 C4E8 59DD 41C1 824C 034C A604 C35A 9408 AAB0` (`SP-DIFFER Release <spdiffe-release@noreply>`)

Expected format:
- one maintainer fingerprint per bullet or line
- full 40-hex OpenPGP fingerprint, with or without spaces

Contributors should verify signed checksums and signed tags against the public key material in the repository root `KEYS` file and the instructions in `SIGNING.md`.
