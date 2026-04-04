#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Shared helpers for semantic adapter case execution."""

import json
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from parse_case import CaseV2, parse_case


ROOT = Path(__file__).resolve().parents[1]
FFI_HELPER = ROOT / "scripts" / "semantic_worker_ffi.py"


def read_case_v2(case_path: Path) -> CaseV2:
    parsed = parse_case(bytes.fromhex(case_path.read_text(encoding="ascii").strip()))
    if not isinstance(parsed, CaseV2):
        raise RuntimeError("{} is not a v2 case".format(case_path))
    return parsed


def build_adapter_command(adapter_cmd: Optional[str], worker_lib: Optional[Path]) -> Tuple[List[str], List[str]]:
    if worker_lib is not None:
        return (
            [sys.executable, str(FFI_HELPER), "--worker-lib", str(worker_lib)],
            ["--worker-lib", str(worker_lib)],
        )
    if adapter_cmd is None:
        raise RuntimeError("missing adapter target")
    command = shlex.split(adapter_cmd)
    if not command:
        raise RuntimeError("empty adapter command")
    return command, ["--adapter-cmd", adapter_cmd]


def run_adapter(command: List[str], request: Dict[str, Any], timeout_seconds: float) -> Dict[str, Any]:
    proc = subprocess.run(
        command,
        input=json.dumps(request, sort_keys=True).encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout_seconds,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "adapter exited with status {}: {}".format(
                proc.returncode, proc.stderr.decode("utf-8", errors="replace").strip()
            )
        )
    try:
        return json.loads(proc.stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError("adapter returned invalid JSON: {}".format(exc))
