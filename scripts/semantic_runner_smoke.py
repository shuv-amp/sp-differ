#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Smoke test the compiled runner/compare semantic v2 dispatch."""

import argparse
import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_SRC = ROOT / "tests" / "fixtures" / "semantic_worker_smoke.cpp"
DEFAULT_RUNNER_BIN = ROOT / "build" / "sp_differ_runner"
DEFAULT_COMPARE_BIN = ROOT / "build" / "sp_differ_compare"
SEND_CASE = ROOT / "tests" / "vectors" / "bip352" / "derived" / "v2" / "official_case_00_send_00.hex"
SEND_EXPECTATION = ROOT / "tests" / "vectors" / "bip352" / "derived" / "v2" / "official_case_00_send_00.expected.json"
RECEIVE_CASE = ROOT / "tests" / "vectors" / "bip352" / "derived" / "v2" / "official_case_00_receive_00.hex"
RECEIVE_EXPECTATION = ROOT / "tests" / "vectors" / "bip352" / "derived" / "v2" / "official_case_00_receive_00.expected.json"
MULTI_SEND_CASE = ROOT / "tests" / "vectors" / "bip352" / "derived" / "v2" / "official_case_15_send_00.hex"
MULTI_SEND_EXPECTATION = (
    ROOT / "tests" / "vectors" / "bip352" / "derived" / "v2" / "official_case_15_send_00.expected.json"
)


def _shared_lib_name(stem: str = "semantic_worker_smoke") -> str:
    if sys.platform == "darwin":
        return "lib{}.dylib".format(stem)
    if sys.platform.startswith("win"):
        return "{}.dll".format(stem)
    return "lib{}.so".format(stem)


def build_fixture(
    out_path: Path,
    response_env: str = "SP_DIFFER_SEMANTIC_SMOKE_RESPONSE",
    cxx: str = "c++",
    cxxflags: str = "-std=c++17 -O2 -fPIC",
) -> None:
    cmd = [
        cxx,
        *shlex.split(cxxflags),
        "-shared",
        "-DSP_DIFFER_SEMANTIC_SMOKE_ENV={}".format(response_env),
        "-o",
        str(out_path),
        str(FIXTURE_SRC),
    ]
    subprocess.check_call(cmd, cwd=ROOT)


def _run_checked(command, env) -> None:
    proc = subprocess.run(
        [str(part) for part in command],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "command failed: {}\nstdout: {}\nstderr: {}".format(
                " ".join(command), proc.stdout.strip(), proc.stderr.strip()
            )
        )


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _run_expect_rc(command, env, expected_rc: int) -> None:
    proc = subprocess.run(
        [str(part) for part in command],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    if proc.returncode != expected_rc:
        raise RuntimeError(
            "command returned {} (expected {})\nstdout: {}\nstderr: {}".format(
                proc.returncode, expected_rc, proc.stdout.strip(), proc.stderr.strip()
            )
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke test compiled semantic runner support")
    parser.add_argument(
        "--runner",
        type=Path,
        default=DEFAULT_RUNNER_BIN,
        help="Runner binary to exercise",
    )
    parser.add_argument(
        "--compare",
        type=Path,
        default=DEFAULT_COMPARE_BIN,
        help="Compare binary to exercise",
    )
    parser.add_argument(
        "--cxx",
        default=os.environ.get("CXX", "c++"),
        help="C++ compiler used for the fixture semantic worker",
    )
    parser.add_argument(
        "--cxxflags",
        default=os.environ.get("CXXFLAGS", "-std=c++17 -O2 -fPIC"),
        help="C++ flags used for the fixture semantic worker build",
    )
    args = parser.parse_args()

    runner_bin = args.runner
    compare_bin = args.compare

    if not runner_bin.is_file():
        print("FAIL: runner binary not found: {}".format(runner_bin), file=sys.stderr)
        return 2
    if not compare_bin.is_file():
        print("FAIL: compare binary not found: {}".format(compare_bin), file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_root = Path(tmp_dir)
        lib_path = tmp_root / _shared_lib_name()
        build_fixture(lib_path, cxx=args.cxx, cxxflags=args.cxxflags)

        left_lib_path = tmp_root / _shared_lib_name("semantic_worker_smoke_left")
        right_lib_path = tmp_root / _shared_lib_name("semantic_worker_smoke_right")
        build_fixture(
            left_lib_path,
            "SP_DIFFER_SEMANTIC_SMOKE_RESPONSE_LEFT",
            cxx=args.cxx,
            cxxflags=args.cxxflags,
        )
        build_fixture(
            right_lib_path,
            "SP_DIFFER_SEMANTIC_SMOKE_RESPONSE_RIGHT",
            cxx=args.cxx,
            cxxflags=args.cxxflags,
        )

        env = dict(os.environ)
        env["PYTHON"] = sys.executable

        env["SP_DIFFER_SEMANTIC_SMOKE_RESPONSE"] = str(SEND_EXPECTATION)
        _run_checked([str(runner_bin), str(SEND_CASE), "--worker", str(lib_path)], env)
        _run_checked(
            [
                str(compare_bin),
                str(SEND_CASE),
                "--left",
                str(lib_path),
                "--right",
                str(lib_path),
            ],
            env,
        )

        env["SP_DIFFER_SEMANTIC_SMOKE_RESPONSE"] = str(RECEIVE_EXPECTATION)
        _run_checked([str(runner_bin), str(RECEIVE_CASE), "--worker", str(lib_path)], env)
        _run_checked(
            [
                str(compare_bin),
                str(RECEIVE_CASE),
                "--left",
                str(lib_path),
                "--right",
                str(lib_path),
            ],
            env,
        )

        multi_send_expected = _load_json(MULTI_SEND_EXPECTATION)
        left_multi_send = dict(multi_send_expected)
        right_multi_send = dict(multi_send_expected)
        left_multi_send["acceptable_output_sets"] = [
            multi_send_expected["acceptable_output_sets"][0]
        ]
        right_multi_send["acceptable_output_sets"] = [
            multi_send_expected["acceptable_output_sets"][1]
        ]
        left_multi_send["output_count_options"] = sorted(
            {len(item) for item in left_multi_send["acceptable_output_sets"]}
        )
        right_multi_send["output_count_options"] = sorted(
            {len(item) for item in right_multi_send["acceptable_output_sets"]}
        )

        left_multi_send_path = tmp_root / "multi_send_left.json"
        right_multi_send_path = tmp_root / "multi_send_right.json"
        _write_json(left_multi_send_path, left_multi_send)
        _write_json(right_multi_send_path, right_multi_send)

        env["SP_DIFFER_SEMANTIC_SMOKE_RESPONSE_LEFT"] = str(left_multi_send_path)
        env["SP_DIFFER_SEMANTIC_SMOKE_RESPONSE_RIGHT"] = str(right_multi_send_path)
        _run_checked(
            [
                str(compare_bin),
                str(MULTI_SEND_CASE),
                "--left",
                str(left_lib_path),
                "--right",
                str(right_lib_path),
            ],
            env,
        )

        both_wrong = dict(multi_send_expected)
        both_wrong["acceptable_output_sets"] = [["00" * 32]]
        both_wrong["output_count_options"] = [1]
        both_wrong_path = tmp_root / "multi_send_both_wrong.json"
        _write_json(both_wrong_path, both_wrong)

        env["SP_DIFFER_SEMANTIC_SMOKE_RESPONSE_LEFT"] = str(both_wrong_path)
        env["SP_DIFFER_SEMANTIC_SMOKE_RESPONSE_RIGHT"] = str(both_wrong_path)
        _run_expect_rc(
            [
                str(compare_bin),
                str(MULTI_SEND_CASE),
                "--left",
                str(left_lib_path),
                "--right",
                str(right_lib_path),
            ],
            env,
            9,
        )

    print("semantic runner smoke OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
