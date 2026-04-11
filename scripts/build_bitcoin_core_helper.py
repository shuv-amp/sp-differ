#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the experimental Bitcoin Core semantic helper against a local checkout."""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple


ROOT = Path(__file__).resolve().parents[1]
HELPER_SOURCE = ROOT / "adapters" / "bitcoin_core_exp" / "bitcoin_sp_semantic_helper.cpp"
DEFAULT_OUT = ROOT / "build" / "bitcoin_core_exp" / "bitcoin_sp_semantic_helper"
REQUIRED_SOURCE_PATHS = (
    Path("CMakeLists.txt"),
    Path("src/common/bip352.h"),
    Path("src/secp256k1/include/secp256k1_silentpayments.h"),
    Path("src/univalue/include/univalue.h"),
)
REQUIRED_BUILD_PATHS = (
    Path("src/bitcoin-build-config.h"),
    Path("src/bitcoin-build-info.h"),
    Path("lib/libbitcoin_clientversion.a"),
    Path("lib/libbitcoin_common.a"),
    Path("lib/libbitcoin_consensus.a"),
    Path("lib/libbitcoin_crypto.a"),
    Path("lib/libbitcoin_util.a"),
    Path("src/univalue/libunivalue.a"),
    Path("src/secp256k1/lib/libsecp256k1.a"),
)
BUILD_TARGETS = (
    "bitcoin_common",
    "bitcoin_util",
    "bitcoin_crypto",
    "bitcoin_consensus",
    "bitcoin_clientversion",
    "univalue",
)


class BuildBitcoinCoreHelperError(Exception):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise BuildBitcoinCoreHelperError(message)


def _resolve_tool(env_name: str, default: str) -> List[str]:
    raw = os.environ.get(env_name) or default
    parts = shlex.split(raw)
    _require(parts, "{} resolved to an empty command".format(env_name))
    executable = shutil.which(parts[0]) or parts[0]
    return [executable, *parts[1:]]


def _validate_checkout(bitcoin_root: Path) -> None:
    for relative in REQUIRED_SOURCE_PATHS:
        target = bitcoin_root / relative
        _require(target.exists(), "bitcoin checkout is missing required path: {}".format(target))


def _required_build_paths(build_dir: Path) -> List[Path]:
    return [build_dir / relative for relative in REQUIRED_BUILD_PATHS]


def _needs_build(build_dir: Path, force_reconfigure: bool) -> bool:
    if force_reconfigure:
        return True
    return any(not path.exists() for path in _required_build_paths(build_dir))


def _configure_command(bitcoin_root: Path, build_dir: Path) -> List[str]:
    return [
        *_resolve_tool("CMAKE", "cmake"),
        "-S",
        str(bitcoin_root),
        "-B",
        str(build_dir),
        "-DENABLE_WALLET=OFF",
        "-DBUILD_GUI=OFF",
        "-DBUILD_TESTS=OFF",
        "-DBUILD_BENCH=OFF",
        "-DBUILD_FUZZ_BINARY=OFF",
        "-DWITH_ZMQ=OFF",
        "-DENABLE_IPC=OFF",
    ]


def _build_command(build_dir: Path, jobs: int | None) -> List[str]:
    command = [
        *_resolve_tool("CMAKE", "cmake"),
        "--build",
        str(build_dir),
        "--target",
        *BUILD_TARGETS,
    ]
    if jobs is not None:
        command.extend(["--parallel", str(jobs)])
    return command


def _third_party_include_dirs(build_dir: Path) -> List[Path]:
    candidates: List[Path] = []
    cache_path = build_dir / "CMakeCache.txt"
    if cache_path.exists():
        for line in cache_path.read_text(encoding="utf-8").splitlines():
            if not line.startswith("Boost_DIR:PATH="):
                continue
            boost_dir = Path(line.split("=", 1)[1].strip())
            for ancestor in (boost_dir, *boost_dir.parents):
                include_dir = ancestor / "include"
                if include_dir.exists() and (include_dir / "boost").exists():
                    candidates.append(include_dir)
            break
    for fallback in (Path("/opt/homebrew/include"), Path("/usr/local/include")):
        if fallback.exists() and (fallback / "boost").exists():
            candidates.append(fallback)

    deduped: List[Path] = []
    seen = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        deduped.append(resolved)
    return deduped


def _compile_command(bitcoin_root: Path, build_dir: Path, out_path: Path) -> List[str]:
    include_dirs = (
        bitcoin_root / "src",
        build_dir / "src",
        bitcoin_root / "src/univalue/include",
        bitcoin_root / "src/secp256k1/include",
    )
    libs = (
        build_dir / "lib/libbitcoin_common.a",
        build_dir / "lib/libbitcoin_consensus.a",
        build_dir / "lib/libbitcoin_util.a",
        build_dir / "lib/libbitcoin_crypto.a",
        build_dir / "lib/libbitcoin_clientversion.a",
        build_dir / "src/univalue/libunivalue.a",
        build_dir / "src/secp256k1/lib/libsecp256k1.a",
    )
    command = [*_resolve_tool("CXX", "c++"), "-std=c++20", "-O2"]
    for include_dir in (*include_dirs, *_third_party_include_dirs(build_dir)):
        command.extend(["-I", str(include_dir)])
    command.extend(
        [
            "-o",
            str(out_path),
            str(HELPER_SOURCE),
            *(str(lib) for lib in libs),
        ]
    )
    return command


def _command_lines(plan: Sequence[Tuple[str, List[str]]]) -> List[str]:
    lines = []
    for label, command in plan:
        lines.append("{}: {}".format(label, shlex.join(command)))
    return lines


def _latest_mtime(paths: Iterable[Path]) -> float:
    return max(path.stat().st_mtime for path in paths if path.exists())


def _helper_is_fresh(bitcoin_root: Path, build_dir: Path, out_path: Path, force_reconfigure: bool) -> bool:
    if force_reconfigure or not out_path.exists():
        return False
    inputs = [HELPER_SOURCE]
    inputs.extend(bitcoin_root / relative for relative in REQUIRED_SOURCE_PATHS)
    inputs.extend(_required_build_paths(build_dir))
    if any(not path.exists() for path in inputs):
        return False
    return out_path.stat().st_mtime >= _latest_mtime(inputs)


def _run(command: List[str]) -> None:
    proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True)
    if proc.returncode != 0:
        raise BuildBitcoinCoreHelperError(
            "command failed ({}): {}".format(
                proc.returncode,
                (proc.stderr or proc.stdout).strip() or shlex.join(command),
            )
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the experimental Bitcoin Core helper")
    parser.add_argument(
        "--bitcoin-root",
        type=Path,
        required=True,
        help="Path to the local Bitcoin Core checkout",
    )
    parser.add_argument(
        "--bitcoin-build-dir",
        type=Path,
        help="Optional Bitcoin Core build directory; defaults to <bitcoin-root>/build",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help="Helper output path",
    )
    parser.add_argument("--jobs", type=int, help="Optional parallel build job count")
    parser.add_argument(
        "--force-reconfigure",
        action="store_true",
        help="Always rerun the upstream configure/build commands before compiling the helper",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the planned commands without executing them",
    )
    args = parser.parse_args()

    try:
        bitcoin_root = args.bitcoin_root.resolve()
        build_dir = (args.bitcoin_build_dir or (bitcoin_root / "build")).resolve()
        out_path = args.out.resolve()

        _require(out_path.name and not out_path.name.startswith("-"), "refusing output path that starts with '-'")
        _validate_checkout(bitcoin_root)

        plan: List[Tuple[str, List[str]]] = []
        if _needs_build(build_dir, args.force_reconfigure):
            plan.append(("configure", _configure_command(bitcoin_root, build_dir)))
            plan.append(("build", _build_command(build_dir, args.jobs)))
        compile_command = _compile_command(bitcoin_root, build_dir, out_path)
        plan.append(("compile", compile_command))

        if args.dry_run:
            print("\n".join(_command_lines(plan)))
            return 0

        out_path.parent.mkdir(parents=True, exist_ok=True)
        if _helper_is_fresh(bitcoin_root, build_dir, out_path, args.force_reconfigure):
            print("bitcoin core helper is up to date")
            print("  output: {}".format(out_path))
            return 0

        for _, command in plan[:-1]:
            _run(command)
        for required in _required_build_paths(build_dir):
            _require(required.exists(), "bitcoin build is missing required artifact: {}".format(required))
        _run(compile_command)

        _require(out_path.exists(), "helper build did not produce {}".format(out_path))
        print("bitcoin core helper build OK")
        print("  output: {}".format(out_path))
        return 0
    except BuildBitcoinCoreHelperError as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
