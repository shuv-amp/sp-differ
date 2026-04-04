#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate and normalize semantic artifacts for official BIP352 cases."""
from collections import Counter
from typing import Any, Dict, Iterable, List, Sequence, Tuple

from bip352_vectors import classify_input_type
from parse_case import CaseV2, parse_case
from semantic_contract import SEMANTIC_CONTRACT_VERSION, normalize_semantic_result


FLAG_INPUT_PRIVATE_KEYS = 1 << 1
FLAG_PREVOUT_SCRIPT_PUBKEYS = 1 << 3
FLAG_SCRIPT_SIGS = 1 << 4
FLAG_TXINWITNESSES = 1 << 5
FLAG_RECIPIENT_GROUPS = 1 << 6
FLAG_OUTPUTS_TO_SCAN = 1 << 7
FLAG_RECEIVER_KEY_MATERIAL = 1 << 8

INPUT_TYPE_CODES = {
    "p2wpkh": 0x01,
    "p2tr": 0x02,
    "p2sh-p2wpkh": 0x03,
    "p2pkh": 0x04,
}


def build_case_id(case_index: int, kind: str, entry_index: int) -> str:
    return "official_case_{:02d}_{}_{:02d}".format(case_index, kind, entry_index)


def build_source(
    upstream_commit: str, case_index: int, kind: str, entry_index: int, comment: str
) -> Dict[str, Any]:
    return {
        "upstream_commit": upstream_commit,
        "case_index": case_index,
        "entry_index": entry_index,
        "kind": kind,
        "comment": comment,
        "id": build_case_id(case_index, kind, entry_index),
    }


def encode_send_case_v2(case_index: int, send_index: int, entry: Dict[str, Any]) -> bytes:
    seed = 0x5300000000000000 | (case_index << 8) | send_index
    flags = (
        FLAG_INPUT_PRIVATE_KEYS
        | FLAG_PREVOUT_SCRIPT_PUBKEYS
        | FLAG_SCRIPT_SIGS
        | FLAG_TXINWITNESSES
        | FLAG_RECIPIENT_GROUPS
    )
    recipients = aggregate_recipient_groups(entry["given"]["recipients"])
    payload = bytearray()
    payload.append(2)
    payload.extend(seed.to_bytes(8, "little"))
    payload.extend(flags.to_bytes(4, "little"))
    payload.extend(len(entry["given"]["vin"]).to_bytes(2, "little"))
    payload.extend(len(recipients).to_bytes(2, "little"))
    payload.extend((0).to_bytes(2, "little"))
    payload.extend((0).to_bytes(2, "little"))

    for vin in entry["given"]["vin"]:
        prevout_script = bytes.fromhex(vin["prevout"]["scriptPubKey"]["hex"])
        script_sig = bytes.fromhex(vin["scriptSig"])
        txinwitness = bytes.fromhex(vin["txinwitness"])
        payload.extend(bytes.fromhex(vin["txid"])[::-1])
        payload.extend(int(vin["vout"]).to_bytes(4, "little"))
        payload.append(INPUT_TYPE_CODES[classify_input_type(vin)])
        _append_var_bytes(payload, prevout_script)
        _append_var_bytes(payload, script_sig)
        _append_var_bytes(payload, txinwitness)
        payload.extend(bytes.fromhex(vin["private_key"]))

    for scan_pubkey, spend_pubkey, count in recipients:
        payload.extend(bytes.fromhex(scan_pubkey))
        payload.extend(bytes.fromhex(spend_pubkey))
        payload.extend(int(count).to_bytes(2, "little"))

    return bytes(payload)


def encode_receive_case_v2(
    case_index: int, receive_index: int, entry: Dict[str, Any]
) -> bytes:
    seed = 0x5200000000000000 | (case_index << 8) | receive_index
    flags = (
        FLAG_PREVOUT_SCRIPT_PUBKEYS
        | FLAG_SCRIPT_SIGS
        | FLAG_TXINWITNESSES
        | FLAG_OUTPUTS_TO_SCAN
        | FLAG_RECEIVER_KEY_MATERIAL
    )
    labels = list(entry["given"]["labels"])
    outputs = list(entry["given"]["outputs"])
    payload = bytearray()
    payload.append(2)
    payload.extend(seed.to_bytes(8, "little"))
    payload.extend(flags.to_bytes(4, "little"))
    payload.extend(len(entry["given"]["vin"]).to_bytes(2, "little"))
    payload.extend((0).to_bytes(2, "little"))
    payload.extend(len(outputs).to_bytes(2, "little"))
    payload.extend(len(labels).to_bytes(2, "little"))

    for vin in entry["given"]["vin"]:
        prevout_script = bytes.fromhex(vin["prevout"]["scriptPubKey"]["hex"])
        script_sig = bytes.fromhex(vin["scriptSig"])
        txinwitness = bytes.fromhex(vin["txinwitness"])
        payload.extend(bytes.fromhex(vin["txid"])[::-1])
        payload.extend(int(vin["vout"]).to_bytes(4, "little"))
        payload.append(INPUT_TYPE_CODES[classify_input_type(vin)])
        _append_var_bytes(payload, prevout_script)
        _append_var_bytes(payload, script_sig)
        _append_var_bytes(payload, txinwitness)

    for output in outputs:
        payload.extend(bytes.fromhex(output))

    payload.extend(bytes.fromhex(entry["given"]["key_material"]["scan_priv_key"]))
    payload.extend(bytes.fromhex(entry["given"]["key_material"]["spend_priv_key"]))
    for label in labels:
        payload.extend(int(label).to_bytes(4, "little"))

    return bytes(payload)


def parse_case_v2_payload(payload: bytes) -> CaseV2:
    parsed = parse_case(payload)
    if not isinstance(parsed, CaseV2):
        raise RuntimeError("expected v2 case payload")
    return parsed


def derive_sender_semantics(
    reference_module, case: CaseV2, source: Dict[str, Any]
) -> Dict[str, Any]:
    vins = build_vins(reference_module, case)
    outpoints = [vin.outpoint for vin in vins]
    input_pubkeys = []
    eligible_privkeys = []
    for vin, input_entry in zip(vins, case.inputs):
        pubkey = reference_module.get_pubkey_from_input(vin)
        if pubkey.infinity:
            continue
        input_pubkeys.append(pubkey.to_bytes_compressed().hex())
        if input_entry.privkey:
            eligible_privkeys.append(
                (
                    reference_module.Scalar.from_bytes_checked(bytes(input_entry.privkey)),
                    reference_module.is_p2tr(vin.prevout),
                )
            )

    shared_secret_entries = [
        {"scan_pubkey": item["scan_pubkey"], "shared_secret": None}
        for item in sender_scan_groups(case)
    ]
    payload: Dict[str, Any] = {
        "semantic_contract_version": SEMANTIC_CONTRACT_VERSION,
        "case_format_version": 2,
        "kind": "send",
        "source": source,
        "semantic_status": "ok",
        "input_pubkeys": input_pubkeys,
        "input_hash": None,
        "input_private_key_sum": None,
        "sender_shared_secrets": shared_secret_entries,
        "acceptable_output_sets": [[]],
        "output_count_options": [0],
        "notes": [],
    }

    if not input_pubkeys:
        payload["semantic_status"] = "no_eligible_inputs"
        return normalize_semantic_result(payload)

    negated_keys = []
    for key, is_xonly in eligible_privkeys:
        scalar = reference_module.Scalar.from_bytes_checked(key.to_bytes())
        if is_xonly and not (scalar * reference_module.G).has_even_y():
            scalar = -scalar
        negated_keys.append(scalar)
    a_sum = reference_module.Scalar.sum(*negated_keys)
    payload["input_private_key_sum"] = a_sum.to_bytes().hex()

    if a_sum == 0:
        payload["semantic_status"] = "zero_scalar"
        return normalize_semantic_result(payload)

    input_hash = reference_module.get_input_hash(outpoints, a_sum * reference_module.G)
    payload["input_hash"] = input_hash.hex()
    scan_groups = sender_scan_groups(case)
    if any(len(item["spend_pubkeys"]) > reference_module.K_max for item in scan_groups):
        payload["semantic_status"] = "recipient_limit_exceeded"
        payload["notes"].append("per_group_recipient_limit_exceeded")
        return normalize_semantic_result(payload)

    input_hash_scalar = reference_module.Scalar.from_bytes_checked(input_hash)
    for item in payload["sender_shared_secrets"]:
        b_scan = reference_module.GE.from_bytes_compressed(bytes.fromhex(item["scan_pubkey"]))
        shared_secret = (
            input_hash_scalar * a_sum * b_scan
        ).to_bytes_compressed().hex()
        item["shared_secret"] = shared_secret

    payload["acceptable_output_sets"] = compute_sender_output_sets(
        reference_module, scan_groups, input_hash_scalar, a_sum
    )
    payload["output_count_options"] = sorted(
        {len(output_set) for output_set in payload["acceptable_output_sets"]}
    )
    if len(payload["acceptable_output_sets"]) > 1:
        payload["notes"].append("multiple_valid_output_sets")
    return normalize_semantic_result(payload)


def derive_receive_semantics(
    reference_module,
    case: CaseV2,
    source: Dict[str, Any],
    detailed_outputs_available: bool,
) -> Dict[str, Any]:
    vins = build_vins(reference_module, case)
    outpoints = [vin.outpoint for vin in vins]
    input_pubkeys_ge = []
    input_pubkeys = []
    for vin in vins:
        pubkey = reference_module.get_pubkey_from_input(vin)
        if pubkey.infinity:
            continue
        input_pubkeys_ge.append(pubkey)
        input_pubkeys.append(pubkey.to_bytes_compressed().hex())

    b_scan = reference_module.Scalar.from_bytes_checked(bytes(case.receiver_keys.scan_privkey))
    b_spend = reference_module.Scalar.from_bytes_checked(bytes(case.receiver_keys.spend_privkey))
    b_scan_ge = b_scan * reference_module.G
    b_spend_ge = b_spend * reference_module.G
    addresses = [
        reference_module.encode_silent_payment_address(b_scan_ge, b_spend_ge, hrp="sp")
    ]
    for label in case.labels:
        addresses.append(
            reference_module.create_labeled_silent_payment_address(
                b_scan, b_spend_ge, int(label), hrp="sp"
            )
        )

    payload: Dict[str, Any] = {
        "semantic_contract_version": SEMANTIC_CONTRACT_VERSION,
        "case_format_version": 2,
        "kind": "receive",
        "source": source,
        "semantic_status": "ok",
        "input_pubkeys": input_pubkeys,
        "input_hash": None,
        "receiving_addresses": addresses,
        "input_pubkey_sum": None,
        "tweak": None,
        "shared_secret": None,
        "detailed_outputs_available": detailed_outputs_available,
        "found_output_count": 0,
        "found_outputs": [],
        "notes": [],
    }

    if not input_pubkeys_ge:
        payload["semantic_status"] = "no_eligible_inputs"
        return normalize_semantic_result(payload)

    a_sum = reference_module.GE.sum(*input_pubkeys_ge)
    if a_sum.infinity:
        payload["semantic_status"] = "point_at_infinity"
        return normalize_semantic_result(payload)

    input_hash = reference_module.get_input_hash(outpoints, a_sum)
    input_hash_scalar = reference_module.Scalar.from_bytes_checked(input_hash)
    payload["input_hash"] = input_hash.hex()
    payload["input_pubkey_sum"] = a_sum.to_bytes_compressed().hex()
    payload["tweak"] = (input_hash_scalar * a_sum).to_bytes_compressed().hex()
    payload["shared_secret"] = (
        input_hash_scalar * b_scan * a_sum
    ).to_bytes_compressed().hex()

    labels = {
        (
            reference_module.generate_label(b_scan, int(label)) * reference_module.G
        ).to_bytes_compressed().hex(): reference_module.generate_label(
            b_scan, int(label)
        ).to_bytes().hex()
        for label in case.labels
    }
    outputs_to_check = [bytes(output) for output in case.outputs_to_scan]
    wallet = reference_module.scanning(
        b_scan=b_scan,
        B_spend=b_spend_ge,
        A_sum=a_sum,
        input_hash=input_hash,
        outputs_to_check=outputs_to_check,
        labels=labels,
        expected={
            "tweak": payload["tweak"],
            "shared_secret": payload["shared_secret"],
        },
    )
    payload["found_output_count"] = len(wallet)
    if detailed_outputs_available:
        payload["found_outputs"] = [
            {"pub_key": item["pub_key"], "priv_key_tweak": item["priv_key_tweak"]}
            for item in wallet
        ]
    if len(case.outputs_to_scan) > reference_module.K_max and len(wallet) == reference_module.K_max:
        payload["notes"].append("scan_limit_reached")
    if not detailed_outputs_available:
        payload["notes"].append("count_only_expectation")
    return normalize_semantic_result(payload)


def compare_sender_semantics_to_official(
    payload: Dict[str, Any], entry: Dict[str, Any]
) -> None:
    expected = entry["expected"]
    if payload["input_pubkeys"] != expected["input_pub_keys"]:
        raise RuntimeError("sender input_pubkeys did not match official expected")

    official_output_sets = []
    for output_set in expected["outputs"]:
        official_output_sets.append(sorted(set(output_set)))
    official_output_sets = sorted(
        {tuple(output_set) for output_set in official_output_sets}
    )
    if [list(item) for item in official_output_sets] != payload["acceptable_output_sets"]:
        raise RuntimeError("sender acceptable_output_sets did not match official expected")

    official_shared_secrets = []
    seen = set()
    for recipient, shared_secret in zip(entry["given"]["recipients"], expected["shared_secrets"]):
        scan_pubkey = recipient["scan_pub_key"]
        if scan_pubkey in seen:
            continue
        seen.add(scan_pubkey)
        official_shared_secrets.append(
            {"scan_pubkey": scan_pubkey, "shared_secret": shared_secret}
        )
    official_shared_secrets.sort(key=lambda item: item["scan_pubkey"])
    if official_shared_secrets != payload["sender_shared_secrets"]:
        raise RuntimeError("sender shared secrets did not match official expected")


def compare_receive_semantics_to_official(
    payload: Dict[str, Any], entry: Dict[str, Any]
) -> None:
    expected = entry["expected"]
    if payload["receiving_addresses"] != expected["addresses"]:
        raise RuntimeError("receive addresses did not match official expected")

    for key in ("tweak", "shared_secret", "input_pub_key_sum"):
        expected_value = expected.get(key)
        payload_key = {
            "tweak": "tweak",
            "shared_secret": "shared_secret",
            "input_pub_key_sum": "input_pubkey_sum",
        }[key]
        if payload.get(payload_key) != expected_value:
            raise RuntimeError("{} did not match official expected".format(key))

    if "outputs" in expected:
        expected_outputs = sorted(
            {
                (item["pub_key"], item["priv_key_tweak"])
                for item in expected["outputs"]
            }
        )
        payload_outputs = sorted(
            (item["pub_key"], item["priv_key_tweak"]) for item in payload["found_outputs"]
        )
        if expected_outputs != payload_outputs:
            raise RuntimeError("receive found_outputs did not match official expected")
    else:
        if payload["found_output_count"] != expected["n_outputs"]:
            raise RuntimeError("receive found_output_count did not match official expected")


def aggregate_recipient_groups(
    recipients: Sequence[Dict[str, Any]]
) -> List[Tuple[str, str, int]]:
    groups: List[List[Any]] = []
    indexes: Dict[Tuple[str, str], int] = {}
    for recipient in recipients:
        key = (recipient["scan_pub_key"], recipient["spend_pub_key"])
        count = int(recipient.get("count", 1))
        if key not in indexes:
            indexes[key] = len(groups)
            groups.append([key[0], key[1], 0])
        groups[indexes[key]][2] += count
    return [(item[0], item[1], int(item[2])) for item in groups]


def sender_scan_groups(case: CaseV2) -> List[Dict[str, Any]]:
    groups: Dict[str, List[str]] = {}
    for group in case.recipient_groups:
        scan_pubkey = bytes(group.scan_pubkey).hex()
        spend_pubkey = bytes(group.spend_pubkey).hex()
        groups.setdefault(scan_pubkey, []).extend([spend_pubkey] * int(group.count))
    return [
        {"scan_pubkey": scan_pubkey, "spend_pubkeys": spend_pubkeys}
        for scan_pubkey, spend_pubkeys in sorted(groups.items())
    ]


def build_vins(reference_module, case: CaseV2):
    vins = []
    for input_entry in case.inputs:
        txinwitness = reference_module.CTxInWitness().deserialize(
            reference_module.from_hex(bytes(input_entry.txinwitness).hex())
        )
        private_key = None
        if input_entry.privkey:
            private_key = reference_module.Scalar.from_bytes_checked(
                bytes(input_entry.privkey)
            )
        vins.append(
            reference_module.VinInfo(
                outpoint=reference_module.COutPoint(
                    hash=bytes(input_entry.outpoint_txid),
                    n=int(input_entry.outpoint_vout),
                ),
                scriptSig=bytes(input_entry.script_sig),
                txinwitness=txinwitness,
                prevout=bytes(input_entry.prevout_script_pubkey),
                private_key=private_key,
            )
        )
    return vins


def compute_sender_output_sets(
    reference_module, scan_groups: Sequence[Dict[str, Any]], input_hash_scalar, a_sum
) -> List[List[str]]:
    grouped_output_sets: List[List[Tuple[str, ...]]] = []
    for group in scan_groups:
        scan_pubkey = group["scan_pubkey"]
        spend_pubkeys = list(group["spend_pubkeys"])
        b_scan = reference_module.GE.from_bytes_compressed(bytes.fromhex(scan_pubkey))
        shared_secret = input_hash_scalar * a_sum * b_scan
        output_sets = set()
        for permutation in unique_permutations(spend_pubkeys):
            outputs = []
            for index, spend_pubkey in enumerate(permutation):
                b_m = reference_module.GE.from_bytes_compressed(bytes.fromhex(spend_pubkey))
                tweak = reference_module.Scalar.from_bytes_checked(
                    reference_module.tagged_hash(
                        "BIP0352/SharedSecret",
                        shared_secret.to_bytes_compressed()
                        + reference_module.ser_uint32(index),
                    )
                )
                outputs.append((b_m + tweak * reference_module.G).to_bytes_xonly().hex())
            output_sets.add(tuple(sorted(set(outputs))))
        grouped_output_sets.append(sorted(output_sets))

    full_sets = {tuple()}
    for output_sets in grouped_output_sets:
        next_sets = set()
        for prefix in full_sets:
            prefix_items = set(prefix)
            for output_set in output_sets:
                next_sets.add(tuple(sorted(prefix_items.union(output_set))))
        full_sets = next_sets

    return [list(item) for item in sorted(full_sets)]


def unique_permutations(items: Sequence[str]) -> Iterable[Tuple[str, ...]]:
    counts = Counter(items)
    ordered_keys = sorted(counts)
    size = len(items)

    def _walk(path: List[str]):
        if len(path) == size:
            yield tuple(path)
            return
        for key in ordered_keys:
            if counts[key] == 0:
                continue
            counts[key] -= 1
            path.append(key)
            yield from _walk(path)
            path.pop()
            counts[key] += 1

    return _walk([])


def _append_var_bytes(payload: bytearray, data: bytes) -> None:
    payload.extend(len(data).to_bytes(2, "little"))
    payload.extend(data)
