#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: scripts/sign_release.sh --input-dir <dir> [--output-dir <dir>] [--gpg-key <key-id>] [--allow-unsigned]

Generates SHA256SUMS for release binaries in the input directory and, by default,
creates an armored detached GPG signature for the checksum file.

Options:
  --input-dir <dir>      Directory containing release binaries.
  --output-dir <dir>     Directory for SHA256SUMS artifacts. Defaults to input dir.
  --gpg-key <key-id>     GPG key id or fingerprint to use for signing.
  --allow-unsigned       Generate SHA256SUMS without a signature when no key is available.
  --help                 Show this help text.
EOF
}

input_dir=""
output_dir=""
gpg_key="${GPG_KEY_ID:-}"
allow_unsigned=0
sum_file="SHA256SUMS"
sig_file="SHA256SUMS.asc"
gpg_passphrase="${GPG_PASSPHRASE:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --input-dir)
      input_dir="${2:-}"
      shift 2
      ;;
    --output-dir)
      output_dir="${2:-}"
      shift 2
      ;;
    --gpg-key)
      gpg_key="${2:-}"
      shift 2
      ;;
    --allow-unsigned)
      allow_unsigned=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$input_dir" ]]; then
  echo "error: --input-dir is required" >&2
  usage >&2
  exit 2
fi

if [[ ! -d "$input_dir" ]]; then
  echo "error: input directory does not exist: $input_dir" >&2
  exit 1
fi

if [[ -z "$output_dir" ]]; then
  output_dir="$input_dir"
fi
mkdir -p "$output_dir"

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print $1}'
    return
  fi
  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$path" | awk '{print $NF}'
    return
  fi
  echo "error: no SHA256 tool found (sha256sum, shasum, or openssl)" >&2
  exit 1
}

binaries=()
while IFS= read -r line; do
  binaries+=("$line")
done < <(
  cd "$input_dir"
  find . -maxdepth 1 -type f \
    \( -perm -111 -o -name '*.so' -o -name '*.dylib' -o -name '*.dll' \) \
    ! -name "$sum_file" ! -name "$sig_file" \
    -print | sed 's#^\./##' | LC_ALL=C sort
)

if [[ ${#binaries[@]} -eq 0 ]]; then
  echo "error: no release binaries found in $input_dir" >&2
  exit 1
fi

sum_path="$output_dir/$sum_file"
sig_path="$output_dir/$sig_file"
: > "$sum_path"
for binary in "${binaries[@]}"; do
  checksum="$(sha256_file "$input_dir/$binary")"
  printf '%s  %s\n' "$checksum" "$binary" >> "$sum_path"
done

if [[ -n "$gpg_key" ]]; then
  if ! command -v gpg >/dev/null 2>&1; then
    echo "error: gpg is required for signing" >&2
    exit 1
  fi
  gpg_args=(
    --batch
    --yes
    --armor
    --local-user "$gpg_key"
    --output "$sig_path"
  )
  if [[ -n "$gpg_passphrase" ]]; then
    gpg_args+=(--pinentry-mode loopback --passphrase-fd 0)
  fi
  if [[ -n "$gpg_passphrase" ]]; then
    printf '%s' "$gpg_passphrase" | gpg "${gpg_args[@]}" --detach-sign "$sum_path"
  else
    gpg "${gpg_args[@]}" --detach-sign "$sum_path"
  fi
elif [[ "$allow_unsigned" -ne 1 ]]; then
  echo "error: --gpg-key (or GPG_KEY_ID) is required unless --allow-unsigned is set" >&2
  exit 1
fi

if [[ "$allow_unsigned" -eq 1 && -z "$gpg_key" ]]; then
  echo "warning: generated unsigned SHA256SUMS at $sum_path" >&2
else
  echo "signed release checksums at $sum_path and $sig_path"
fi
