#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Heuristic semantic fuzz coverage reporting inspired by Fuzz Introspector."""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from bip352_reference import load_reference_module
from bip352_semantics import derive_receive_semantics, derive_sender_semantics
from bip352_vectors import write_json
from semantic_adapter import (
    INPUT_TYPE_NAMES,
    KNOWN_NETWORKS,
    case_from_semantic_request,
    validate_semantic_request,
)
from semantic_contract import KNOWN_STATUSES, validate_semantic_result


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS_ROOT = ROOT / "fuzz" / "corpus" / "semantic_worker"
DEFAULT_REFERENCE = ROOT / "tests" / "vectors" / "bip352" / "official" / "reference" / "reference.py"
DEFAULT_ERROR_SURFACE_MANIFEST = ROOT / "tests" / "error_surfaces" / "semantic" / "manifest.json"


class SemanticFuzzIntrospectorError(Exception):
    pass


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_reference_module():
    return load_reference_module(DEFAULT_REFERENCE, DEFAULT_REFERENCE.parent)


def _run_reference(reference_module, request: Dict[str, Any]) -> Dict[str, Any]:
    normalized_request = validate_semantic_request(request)
    case = case_from_semantic_request(normalized_request)
    if normalized_request["kind"] == "send":
        result = derive_sender_semantics(reference_module, case, normalized_request["source"])
    else:
        hints = normalized_request.get("expectation_hints") or {}
        result = derive_receive_semantics(
            reference_module,
            case,
            normalized_request["source"],
            detailed_outputs_available=bool(hints.get("detailed_outputs_required", True)),
        )
    return validate_semantic_result(result)


def _bucket_count(value: int) -> str:
    if value <= 0:
        return "0"
    if value == 1:
        return "1"
    return "2+"


def _joined_input_types(request: Dict[str, Any]) -> str:
    values = sorted({item["input_type"] for item in request["inputs"]})
    return ",".join(values) if values else "none"


def _metadata_flags(request: Dict[str, Any]) -> Dict[str, bool]:
    return {
        "privkey": any(item.get("privkey") is not None for item in request["inputs"]),
        "pubkey": any(item.get("pubkey") is not None for item in request["inputs"]),
        "prevout_script_pubkey": any(
            item.get("prevout_script_pubkey") not in (None, "") for item in request["inputs"]
        ),
        "script_sig": any(item.get("script_sig") not in (None, "") for item in request["inputs"]),
        "txinwitness": any(
            item.get("txinwitness") not in (None, "")
            or bool(item.get("txinwitness_stack"))
            for item in request["inputs"]
        ),
    }


def _path_signature(request: Dict[str, Any], result: Dict[str, Any]) -> str:
    base = [
        request["kind"],
        "status={}".format(result["semantic_status"]),
        "network={}".format(request["network"]),
        "version={}".format("0" if int(request["silent_payment_version"]) == 0 else "nonzero"),
        "input_types={}".format(_joined_input_types(request)),
        "eligible_inputs={}".format(_bucket_count(len(result["input_pubkeys"]))),
    ]
    if request["kind"] == "send":
        recipient_groups = request["recipient_groups"]
        total_recipients = sum(int(group["count"]) for group in recipient_groups)
        base.extend(
            [
                "groups={}".format(_bucket_count(len(recipient_groups))),
                "recipients={}".format(_bucket_count(total_recipients)),
                "repeat_count={}".format(
                    "yes" if any(int(group["count"]) > 1 for group in recipient_groups) else "no"
                ),
            ]
        )
    else:
        hints = request.get("expectation_hints") or {}
        base.extend(
            [
                "outputs={}".format(_bucket_count(len(request.get("outputs_to_scan", [])))),
                "labels={}".format(_bucket_count(len(request.get("labels", [])))),
                "count_only={}".format(
                    "yes" if not bool(hints.get("detailed_outputs_required", True)) else "no"
                ),
            ]
        )
    return "|".join(base)


def _resolve_manifest_path(raw: Optional[Path], generated_from: Dict[str, Any], key: str) -> Optional[Path]:
    if raw is not None:
        return raw
    value = generated_from.get(key)
    if isinstance(value, str) and value:
        return ROOT / value
    return None


def _tracked_universe(
    derived_manifest_path: Optional[Path], regression_manifest_path: Optional[Path]
) -> Dict[str, Any]:
    tracked_ids: List[str] = []
    seen: Set[str] = set()

    if derived_manifest_path is not None and derived_manifest_path.exists():
        derived_manifest = _load_json(derived_manifest_path)
        for item in derived_manifest.get("cases", []):
            case_id = item.get("id")
            if isinstance(case_id, str) and case_id and case_id not in seen:
                tracked_ids.append(case_id)
                seen.add(case_id)

    if regression_manifest_path is not None and regression_manifest_path.exists():
        regression_manifest = _load_json(regression_manifest_path)
        for item in regression_manifest.get("cases", []):
            case_id = item.get("id")
            if isinstance(case_id, str) and case_id and case_id not in seen:
                tracked_ids.append(case_id)
                seen.add(case_id)

    tracked_ids.sort()
    return {
        "expected_seed_count": len(tracked_ids),
        "expected_seed_ids": tracked_ids,
        "derived_manifest": None if derived_manifest_path is None else str(derived_manifest_path),
        "regression_manifest": None
        if regression_manifest_path is None
        else str(regression_manifest_path),
    }


def _error_surface_coverage(manifest_path: Optional[Path]) -> Dict[str, Any]:
    if manifest_path is None or not manifest_path.exists():
        return {
            "manifest": None if manifest_path is None else str(manifest_path),
            "covered_statuses": [],
            "case_ids": [],
            "runtime_case_ids": [],
        }

    manifest = _load_json(manifest_path)
    if manifest.get("semantic_error_surface_version") != 1:
        raise SemanticFuzzIntrospectorError("unsupported semantic error surface manifest version")

    covered_statuses: Set[str] = set()
    case_ids: List[str] = []
    runtime_case_ids: List[str] = []

    for item in manifest.get("cases", []):
        status = item.get("semantic_status")
        case_id = item.get("id")
        if isinstance(status, str):
            covered_statuses.add(status)
        if isinstance(case_id, str) and case_id:
            case_ids.append(case_id)

    for item in manifest.get("byte_worker_cases", []):
        status = item.get("semantic_status")
        case_id = item.get("id")
        if isinstance(status, str):
            covered_statuses.add(status)
        if isinstance(case_id, str) and case_id:
            runtime_case_ids.append(case_id)

    return {
        "manifest": str(manifest_path),
        "covered_statuses": sorted(covered_statuses),
        "case_ids": sorted(case_ids),
        "runtime_case_ids": sorted(runtime_case_ids),
    }


def _gap_suggestion(dimension: str, missing_value: str, representative_ids: Dict[str, Optional[str]]) -> str:
    if dimension == "network":
        return "Mutate any valid seed's network to {} and replay it through semantic adapter fuzz.".format(
            missing_value
        )
    if dimension == "silent_payment_version":
        return "Mutate any valid seed to silent_payment_version=1 and replay it through semantic adapter fuzz."
    if dimension == "semantic_status":
        if missing_value in {"invalid_input", "invalid_pubkey", "tweak_out_of_range", "internal"}:
            return "This status is part of the semantic contract enum but is not exercised by the current valid structured corpus. Add a targeted regression or raw worker seed if it should stay supported."
        return "Promote or synthesize a structured seed that reaches semantic_status={} and keep it in the tracked regression suite.".format(
            missing_value
        )
    if dimension == "input_type":
        return "Start from {} and mutate one input to {}.".format(
            representative_ids.get("send") or representative_ids.get("receive") or "a valid seed",
            missing_value,
        )
    if dimension == "metadata_field":
        return "Add {} material to a valid seed and verify adapters preserve semantic parity.".format(
            missing_value
        )
    if dimension == "receive_shape":
        return "Start from {} and mutate the receive request to exercise {}.".format(
            representative_ids.get("receive") or "a valid receive seed",
            missing_value,
        )
    if dimension == "send_shape":
        return "Start from {} and mutate the send request to exercise {}.".format(
            representative_ids.get("send") or "a valid send seed",
            missing_value,
        )
    return "Add a targeted seed or retained regression that exercises this missing semantic path."


def _build_gap_candidates(
    represented: Dict[str, Counter],
    representative_ids: Dict[str, Optional[str]],
    separately_covered_statuses: Set[str],
) -> List[Dict[str, Any]]:
    gaps: List[Dict[str, Any]] = []

    for network in sorted(KNOWN_NETWORKS):
        if represented["network"][network] == 0:
            gaps.append(
                {
                    "dimension": "network",
                    "missing_value": network,
                    "suggestion": _gap_suggestion("network", network, representative_ids),
                }
            )

    if represented["silent_payment_version_class"]["nonzero"] == 0:
        gaps.append(
            {
                "dimension": "silent_payment_version",
                "missing_value": "nonzero",
                "suggestion": _gap_suggestion(
                    "silent_payment_version", "nonzero", representative_ids
                ),
            }
        )

    for status in sorted(KNOWN_STATUSES):
        if status in separately_covered_statuses:
            continue
        if represented["semantic_status"][status] == 0:
            gaps.append(
                {
                    "dimension": "semantic_status",
                    "missing_value": status,
                    "suggestion": _gap_suggestion("semantic_status", status, representative_ids),
                }
            )

    for input_type in sorted(INPUT_TYPE_NAMES.values()):
        if represented["input_type"][input_type] == 0:
            gaps.append(
                {
                    "dimension": "input_type",
                    "missing_value": input_type,
                    "suggestion": _gap_suggestion("input_type", input_type, representative_ids),
                }
            )

    for field in ("privkey", "pubkey", "prevout_script_pubkey", "script_sig", "txinwitness"):
        if represented["metadata_field"][field] == 0:
            gaps.append(
                {
                    "dimension": "metadata_field",
                    "missing_value": field,
                    "suggestion": _gap_suggestion("metadata_field", field, representative_ids),
                }
            )

    if represented["send_shape"]["multi_group"] == 0:
        gaps.append(
            {
                "dimension": "send_shape",
                "missing_value": "multi_group",
                "suggestion": _gap_suggestion("send_shape", "multi_group", representative_ids),
            }
        )
    if represented["send_shape"]["repeated_recipient_count"] == 0:
        gaps.append(
            {
                "dimension": "send_shape",
                "missing_value": "repeated_recipient_count",
                "suggestion": _gap_suggestion(
                    "send_shape", "repeated_recipient_count", representative_ids
                ),
            }
        )
    if represented["receive_shape"]["labeled"] == 0:
        gaps.append(
            {
                "dimension": "receive_shape",
                "missing_value": "labeled",
                "suggestion": _gap_suggestion("receive_shape", "labeled", representative_ids),
            }
        )
    if represented["receive_shape"]["count_only_expectation"] == 0:
        gaps.append(
            {
                "dimension": "receive_shape",
                "missing_value": "count_only_expectation",
                "suggestion": _gap_suggestion(
                    "receive_shape", "count_only_expectation", representative_ids
                ),
            }
        )

    return gaps


def _render_markdown(report: Dict[str, Any], top_paths: int) -> str:
    lines = [
        "# Semantic Fuzz Introspection",
        "",
        "This report is structure-aware and oracle-backed, but it is not compiler-instrumented coverage.",
        "",
        "- valid_seeds: `{}`".format(report["valid_seed_count"]),
        "- tracked_seed_ids: `{}`".format(report["tracked_universe"]["expected_seed_count"]),
        "- missing_tracked_seed_ids: `{}`".format(
            len(report["tracked_universe"]["missing_seed_ids"])
        ),
        "- gap_candidates: `{}`".format(len(report["gap_candidates"])),
        "",
        "## Tracked Universe",
        "",
    ]
    if report["tracked_universe"]["missing_seed_ids"]:
        for case_id in report["tracked_universe"]["missing_seed_ids"][:16]:
            lines.append("- missing: `{}`".format(case_id))
    else:
        lines.append("All tracked derived/regression ids are seeded in the current corpus.")
    lines.extend(["", "## Represented Dimensions", ""])
    for key in (
        "kind",
        "network",
        "silent_payment_version_class",
        "semantic_status",
        "input_type",
        "metadata_field",
    ):
        lines.append("### `{}`".format(key))
        lines.append("")
        for value, count in report["represented"][key].items():
            lines.append("- `{}`: `{}`".format(value, count))
        lines.append("")

    lines.extend(["## Separate Error Surfaces", ""])
    error_surface = report["error_surface"]
    if error_surface["covered_statuses"]:
        lines.append(
            "Reserved semantic statuses covered outside the valid corpus: `{}`".format(
                ", ".join(error_surface["covered_statuses"])
            )
        )
    else:
        lines.append("No separate semantic error-surface coverage is configured.")
    lines.append("")

    lines.extend(["## Top Path Signatures", ""])
    for item in report["top_path_signatures"][:top_paths]:
        lines.append("- `{}` count=`{}` examples=`{}`".format(
            item["signature"],
            item["count"],
            ", ".join(item["example_seed_ids"]),
        ))
    lines.append("")

    lines.extend(["## Gap Candidates", ""])
    if not report["gap_candidates"]:
        lines.append("No gap candidates.")
    else:
        for gap in report["gap_candidates"]:
            lines.append(
                "- `{}` -> `{}`: {}".format(
                    gap["dimension"],
                    gap["missing_value"],
                    gap["suggestion"],
                )
            )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Report heuristic semantic fuzz corpus visibility and blind spots"
    )
    parser.add_argument(
        "--corpus-root",
        type=Path,
        default=DEFAULT_CORPUS_ROOT,
        help="Semantic fuzz corpus root",
    )
    parser.add_argument(
        "--derived-manifest",
        type=Path,
        help="Optional derived-manifest override for tracked-universe accounting",
    )
    parser.add_argument(
        "--regression-manifest",
        type=Path,
        help="Optional regression-manifest override for tracked-universe accounting",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=Path("build/semantic_fuzz_introspection.json"),
        help="Machine-readable report output path",
    )
    parser.add_argument(
        "--markdown-out",
        type=Path,
        default=Path("build/semantic_fuzz_introspection.md"),
        help="Markdown summary output path",
    )
    parser.add_argument(
        "--error-surface-manifest",
        type=Path,
        default=DEFAULT_ERROR_SURFACE_MANIFEST,
        help="Optional semantic error-surface manifest used to suppress reserved-status gaps",
    )
    parser.add_argument(
        "--top-paths",
        type=int,
        default=16,
        help="Number of top path signatures to retain in the JSON and markdown report",
    )
    args = parser.parse_args()

    try:
        manifest = _load_json(args.corpus_root / "manifest.json")
        valid_entries = manifest.get("valid", [])
        if not valid_entries:
            raise SemanticFuzzIntrospectorError("semantic fuzz corpus has no valid seeds")
        generated_from = manifest.get("generated_from") or {}
        derived_manifest = _resolve_manifest_path(
            args.derived_manifest, generated_from, "derived_manifest"
        )
        regression_manifest = _resolve_manifest_path(
            args.regression_manifest, generated_from, "regression_manifest"
        )
        reference_module = _load_reference_module()
        error_surface = _error_surface_coverage(args.error_surface_manifest)
    except Exception as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2

    represented = {
        "kind": Counter(),
        "network": Counter(),
        "silent_payment_version_class": Counter(),
        "semantic_status": Counter(),
        "input_type": Counter(),
        "metadata_field": Counter(),
        "source": Counter(),
        "send_shape": Counter(),
        "receive_shape": Counter(),
    }
    path_counts: Counter[str] = Counter()
    path_examples: Dict[str, List[str]] = defaultdict(list)
    representative_ids = {"send": None, "receive": None}
    corpus_ids: List[str] = []

    for entry in valid_entries:
        request = validate_semantic_request(_load_json(args.corpus_root / entry["path"]))
        result = _run_reference(reference_module, request)
        corpus_ids.append(entry["id"])

        represented["kind"][request["kind"]] += 1
        represented["network"][request["network"]] += 1
        represented["semantic_status"][result["semantic_status"]] += 1
        represented["silent_payment_version_class"][
            "0" if int(request["silent_payment_version"]) == 0 else "nonzero"
        ] += 1
        represented["source"][entry.get("source", "unknown")] += 1
        if representative_ids[request["kind"]] is None:
            representative_ids[request["kind"]] = entry["id"]

        for input_type in {item["input_type"] for item in request["inputs"]}:
            represented["input_type"][input_type] += 1
        for field, present in _metadata_flags(request).items():
            if present:
                represented["metadata_field"][field] += 1

        if request["kind"] == "send":
            groups = request["recipient_groups"]
            if len(groups) > 1:
                represented["send_shape"]["multi_group"] += 1
            if any(int(group["count"]) > 1 for group in groups):
                represented["send_shape"]["repeated_recipient_count"] += 1
        else:
            if request.get("labels"):
                represented["receive_shape"]["labeled"] += 1
            hints = request.get("expectation_hints") or {}
            if not bool(hints.get("detailed_outputs_required", True)):
                represented["receive_shape"]["count_only_expectation"] += 1

        signature = _path_signature(request, result)
        path_counts[signature] += 1
        if len(path_examples[signature]) < 4:
            path_examples[signature].append(entry["id"])

    tracked_universe = _tracked_universe(derived_manifest, regression_manifest)
    tracked_ids = set(tracked_universe["expected_seed_ids"])
    corpus_id_set = set(corpus_ids)
    tracked_universe["corpus_seed_count"] = len(corpus_ids)
    tracked_universe["missing_seed_ids"] = sorted(tracked_ids - corpus_id_set)
    tracked_universe["extra_seed_ids"] = sorted(corpus_id_set - tracked_ids) if tracked_ids else []

    gap_candidates = _build_gap_candidates(
        represented,
        representative_ids,
        set(error_surface["covered_statuses"]),
    )
    top_path_signatures = [
        {
            "signature": signature,
            "count": count,
            "example_seed_ids": path_examples[signature],
        }
        for signature, count in sorted(
            path_counts.items(), key=lambda item: (-item[1], item[0])
        )[: args.top_paths]
    ]

    report = {
        "semantic_fuzz_introspection_version": 1,
        "corpus_root": str(args.corpus_root),
        "valid_seed_count": len(corpus_ids),
        "tracked_universe": tracked_universe,
        "error_surface": error_surface,
        "represented": {key: dict(sorted(counter.items())) for key, counter in represented.items()},
        "top_path_signatures": top_path_signatures,
        "gap_candidates": gap_candidates,
    }

    write_json(args.json_out, report)
    args.markdown_out.write_text(
        _render_markdown(report, args.top_paths) + "\n", encoding="utf-8"
    )

    print("semantic fuzz introspection OK")
    print("  valid seeds: {}".format(report["valid_seed_count"]))
    print("  missing tracked ids: {}".format(len(tracked_universe["missing_seed_ids"])))
    print("  separate error-surface statuses: {}".format(len(error_surface["covered_statuses"])))
    print("  gap candidates: {}".format(len(gap_candidates)))
    print("  wrote report: {}".format(args.json_out))
    print("  wrote markdown: {}".format(args.markdown_out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
