#!/usr/bin/env python3
"""Reference semantic adapter backed by the vendored upstream BIP352 bundle."""

import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from bip352_reference import load_reference_module  # noqa: E402
from bip352_semantics import derive_receive_semantics, derive_sender_semantics  # noqa: E402
from semantic_adapter import case_from_semantic_request, validate_semantic_request  # noqa: E402


def main() -> int:
    try:
        request = validate_semantic_request(json.load(sys.stdin))
        reference_module = load_reference_module(
            REPO_ROOT / "tests/vectors/bip352/official/reference/reference.py",
            REPO_ROOT / "tests/vectors/bip352/official/reference",
        )
        case = case_from_semantic_request(request)
        if request["kind"] == "send":
            result = derive_sender_semantics(reference_module, case, request["source"])
        else:
            result = derive_receive_semantics(
                reference_module,
                case,
                request["source"],
                detailed_outputs_available=True,
                network=request["network"],
            )
        json.dump(result, sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
        return 0
    except Exception as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
