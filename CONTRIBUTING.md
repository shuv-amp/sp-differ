# Contributing

Thank you for your interest in SP-DIFFER. This project aims to be practical, strict, and easy to reproduce.

The standard to aim for here is closer to review-grade systems work than to
"green on my machine." Changes should be easy to reason about, easy to
reproduce, and easy for another reviewer to verify independently.

## Project Priorities

In order:

1. Correctness and deterministic reproduction
2. Reviewability and auditability
3. Release evidence and operator clarity
4. Performance, ergonomics, and new integrations

## How to Contribute

- Open an issue describing the bug, edge case, or idea.
- Provide minimal reproduction steps or a test case when possible.
- Keep discussions focused on correctness, determinism, and interoperability.

## Before Opening a Pull Request

Run the narrowest commands that prove your change and list the exact commands in
the PR:

```bash
make lint
make test
make sanitize-smoke SANITIZE_CXX=clang++
```

If the change is adapter-specific, vector-specific, benchmark-specific, or
release-specific, run the smallest additional target that directly covers the
modified behavior.

## Patch Hygiene

- Keep patches small, focused, and reviewable.
- Make behavior changes and their tests land in the same patch.
- Separate mechanical refactors or formatting-only churn from behavioral changes.
- Do not mix dependency updates with unrelated logic changes unless there is a
  clear correctness reason.
- Write claims in evidence-first language. If a result is measured only in this
  harness, say so plainly.
- Avoid adding nondeterministic behavior, hidden network requirements, or
  machine-specific assumptions.

## Reporting Discrepancies

Please include:
- The input case or a seed that reproduces the issue.
- The implementation versions or commit hashes.
- The exact output mismatch and any logs.

## Code Style and Testing

- Add tests or regression cases when behavior changes.
- Prefer replayable regression artifacts over anecdotal bug descriptions.
- Keep Rust code `rustfmt`-clean and Go code `gofmt`-clean.
- Keep Rust code `clippy`-clean under the repository's `-D warnings` lane.
- Keep Go code `go vet`-clean under the repository's readonly module lane.
- Keep C++ code warning-clean under the repository's strict warning lane.
- Avoid adding non-deterministic behavior.
- If your change affects release evidence, benchmark outputs, or operator-facing readiness claims, update the relevant docs and make sure the new output can be reproduced from the Make targets.

## Review Expectations

- Explain the concrete problem and failure mode.
- Explain why the fix is correct, not just why tests are green.
- Mention the exact commands you ran and the outcome.
- Update docs when behavior, workflow, or operator-facing output changes.
- Respect `.github/CODEOWNERS` for sensitive paths; changes to core semantics, release plumbing, CI, and security docs should not merge without the named owner review once public branch protection is ready for it.
- Respond to review comments directly and keep the branch history coherent.
- Avoid broad cleanup PRs unless they reduce maintenance or review risk in a way
  the diff and test evidence make explicit.

## Security and Keys

Do not use real wallet keys. Only use disposable keys in tests.

If you believe you found a security issue, prefer GitHub private security
advisories when they are available for the repository. Avoid posting sensitive
details publicly before maintainers have had time to assess the report.

## Release Discipline

- Do not describe a candidate as release-ready unless `make maturity-signoff` is green.
- Do not describe a public tag as verified unless its signing key is published in `SECURITY.md` and the tag signature verifies.
