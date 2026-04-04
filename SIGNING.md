# Release Signing

SP-DIFFER release archives are signed with a detached OpenPGP signature over `SHA256SUMS`.

The public verification key for the current repo-local signing workflow is published in `KEYS`, and the fingerprint is:

`3537 C4E8 59DD 41C1 824C 034C A604 C35A 9408 AAB0`

## Generate A Project Signing Key

Use a dedicated release-signing identity, not a personal day-to-day keyring entry:

```bash
export GNUPGHOME="$HOME/.gnupg-sp-differ-release"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"
gpg --quick-generate-key \
  "SP-DIFFER Release <spdiffe-release@noreply>" \
  ed25519 sign 2y
gpg --list-secret-keys --keyid-format LONG
gpg --armor --export 3537C4E859DD41C1824C034CA604C35A9408AAB0 > KEYS
```

If maintainers rotate keys, update `KEYS`, `SECURITY.md`, and this document in the same patch.

Choose a strong passphrase when `gpg` prompts for one. Keep secret-key backups offline, store the passphrase in an OS credential manager rather than the repository, and never commit secret-key exports, keyring directories, or passphrase files to the repository. Only publish `KEYS` and detached signatures.

## Sign A Release Archive

```bash
export GNUPGHOME="$HOME/.gnupg-sp-differ-release"
export RELEASE_SIGN_GPG_KEY="3537C4E859DD41C1824C034CA604C35A9408AAB0"
make package-release SP_DIFFER_BUILD_VERSION=v1.0.0 RELEASE_SIGN_GPG_KEY="$RELEASE_SIGN_GPG_KEY"
make verify-packaged-release SP_DIFFER_BUILD_VERSION=v1.0.0 RELEASE_SIGN_GPG_KEY="$RELEASE_SIGN_GPG_KEY"
```

With the signing key configured, `make verify-packaged-release` should print `signature: verified`.

If the signing key is passphrase-protected, export `GPG_PASSPHRASE` before running the same commands. `scripts/sign_release.sh` uses `gpg --pinentry-mode loopback` and passes the value over stdin rather than exposing it on the command line.

For GitHub Actions, configure all three release-signing secrets together:

- `RELEASE_GPG_PRIVATE_KEY`
- `RELEASE_GPG_KEY_ID`
- `RELEASE_GPG_PASSPHRASE`

## Verify As A Contributor

Import the published public key:

```bash
gpg --import KEYS
```

Verify the packaged archive:

```bash
python3 scripts/verify_packaged_release.py \
  --archive build/sp-differ-v1.0.0-linux-x86_64.tar.gz \
  --require-signature \
  --keys-file KEYS
```

Manual verification is also possible:

```bash
gpg --dearmor < KEYS > /tmp/sp-differ-release.gpg
gpgv --keyring /tmp/sp-differ-release.gpg \
  build/dist/sp-differ-v1.0.0-linux-x86_64/SHA256SUMS.asc \
  build/dist/sp-differ-v1.0.0-linux-x86_64/SHA256SUMS
sha256sum --check build/dist/sp-differ-v1.0.0-linux-x86_64/SHA256SUMS
```
