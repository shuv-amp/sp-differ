# Contributing

Thank you for your interest in SP-DIFFER. This project aims to be practical, strict, and easy to reproduce.

## How to Contribute

- Open an issue describing the bug, edge case, or idea.
- Provide minimal reproduction steps or a test case when possible.
- Keep discussions focused on correctness, determinism, and interoperability.

## Reporting Discrepancies

Please include:
- The input case or a seed that reproduces the issue.
- The implementation versions or commit hashes.
- The exact output mismatch and any logs.

## Code Style and Testing

- Keep changes small and reviewable.
- Add tests or regression cases when behavior changes.
- Avoid adding non-deterministic behavior.
- If your change affects release evidence, benchmark outputs, or operator-facing readiness claims, update the relevant docs and make sure the new output can be reproduced from the Make targets.

## Security and Keys

Do not use real wallet keys. Only use disposable keys in tests.

## Release Discipline

- Do not describe a candidate as release-ready unless `make maturity-signoff` is green.
- Do not describe a public tag as verified unless its signing key is published in `SECURITY.md` and the tag signature verifies.
