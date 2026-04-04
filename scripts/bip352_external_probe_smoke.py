#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Smoke tests for exact-version extraction in the external BIP352 probe."""

import importlib.util
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _load_probe_module():
    spec = importlib.util.spec_from_file_location(
        "bip352_external_probe",
        ROOT / "scripts" / "bip352_external_probe.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load bip352_external_probe.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _resolved_lock_version_smoke(probe, root: Path) -> None:
    project = root / "resolved-lock"
    _write(
        project / "Cargo.toml",
        """[package]
name = "resolved-lock-root"
version = "0.1.0"

[dependencies]
silentpayments = "0.5.0"
""",
    )
    _write(
        project / "Cargo.lock",
        """version = 4

[[package]]
name = "silentpayments"
version = "0.5.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "deadbeef"

[[package]]
name = "resolved-lock-root"
version = "0.1.0"
dependencies = [
 "silentpayments",
]
""",
    )

    original_root = probe.ROOT
    original_http_json = probe._http_json
    probe.ROOT = project
    probe._http_json = lambda _url: {
        "crate": {
            "newest_version": "0.5.1",
            "updated_at": "2026-04-01T00:00:00Z",
            "repository": "https://example.invalid/silentpayments",
        }
    }
    try:
        result = probe._probe_candidate(
            {
                "id": "resolved-lock",
                "name": "resolved lock smoke",
                "integrated_in_repo": True,
                "repo_adapter_name": "resolved-lock",
                "version_tracking": {
                    "kind": "crate",
                    "crate": "silentpayments",
                    "local_manifest": "Cargo.toml",
                    "local_lock": "Cargo.lock",
                    "local_root_package": "resolved-lock-root",
                    "local_dependency": "silentpayments",
                },
            }
        )
    finally:
        probe.ROOT = original_root
        probe._http_json = original_http_json

    _require(result["local_version"] == "0.5.1", "expected lockfile version to win")
    _require(result["local_pin_source"] == "Cargo.lock", "expected Cargo.lock source")
    _require(result["version_status"] == "current", "expected current version status")


def _manifest_fallback_smoke(probe, root: Path) -> None:
    project = root / "manifest-fallback"
    _write(
        project / "Cargo.toml",
        """[package]
name = "manifest-fallback-root"
version = "0.1.0"

[dependencies]
silentpayments = { version = "0.5.0", default-features = false }
""",
    )

    original_root = probe.ROOT
    original_http_json = probe._http_json
    probe.ROOT = project
    probe._http_json = lambda _url: {
        "crate": {
            "newest_version": "0.5.0",
            "updated_at": "2026-04-01T00:00:00Z",
            "repository": "https://example.invalid/silentpayments",
        }
    }
    try:
        result = probe._probe_candidate(
            {
                "id": "manifest-fallback",
                "name": "manifest fallback smoke",
                "integrated_in_repo": True,
                "repo_adapter_name": "manifest-fallback",
                "version_tracking": {
                    "kind": "crate",
                    "crate": "silentpayments",
                    "local_manifest": "Cargo.toml",
                    "local_dependency": "silentpayments",
                },
            }
        )
    finally:
        probe.ROOT = original_root
        probe._http_json = original_http_json

    _require(result["local_version"] == "0.5.0", "expected manifest fallback version")
    _require(result["local_pin_source"] == "Cargo.toml", "expected manifest source")
    _require(result["version_status"] == "current", "expected current fallback status")


def _multi_version_lock_smoke(probe, root: Path) -> None:
    lock_path = root / "multi-version" / "Cargo.lock"
    _write(
        lock_path,
        """version = 4

[[package]]
name = "bech32"
version = "0.10.0-beta"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaa"

[[package]]
name = "bech32"
version = "0.11.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbb"

[[package]]
name = "multi-version-root"
version = "0.1.0"
dependencies = [
 "bech32 0.11.1",
]
""",
    )

    version = probe._extract_cargo_lock_dependency_version(
        lock_path,
        "multi-version-root",
        "bech32",
    )
    _require(
        version == "0.11.1",
        "expected root dependency entry to disambiguate multi-version lockfile",
    )


def main() -> int:
    probe = _load_probe_module()
    with tempfile.TemporaryDirectory(prefix="sp-differ-external-probe-smoke-") as tmpdir:
        root = Path(tmpdir)
        _resolved_lock_version_smoke(probe, root)
        _manifest_fallback_smoke(probe, root)
        _multi_version_lock_smoke(probe, root)
    print("bip352 external probe smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
