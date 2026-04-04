#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Helpers for vendored official BIP352 test vectors."""

import hashlib
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


UPSTREAM_REPO = "https://github.com/bitcoin/bips"
UPSTREAM_BRANCH = "master"
UPSTREAM_BRANCH_API_URL = "https://api.github.com/repos/bitcoin/bips/branches/master"
VECTOR_RELATIVE_PATH = "bip-0352/send_and_receive_test_vectors.json"
REFERENCE_RELATIVE_PATH = "bip-0352/reference.py"
REFERENCE_BUNDLE_FILES: Tuple[Tuple[str, str], ...] = (
    ("bip-0352/reference.py", "reference/reference.py"),
    ("bip-0352/bitcoin_utils.py", "reference/bitcoin_utils.py"),
    ("bip-0352/bech32m.py", "reference/bech32m.py"),
    ("bip-0352/ripemd160.py", "reference/ripemd160.py"),
    ("bip-0352/secp256k1lab/COPYING", "reference/secp256k1lab/COPYING"),
    (
        "bip-0352/secp256k1lab/src/secp256k1lab/__init__.py",
        "reference/secp256k1lab/src/secp256k1lab/__init__.py",
    ),
    (
        "bip-0352/secp256k1lab/src/secp256k1lab/bip340.py",
        "reference/secp256k1lab/src/secp256k1lab/bip340.py",
    ),
    (
        "bip-0352/secp256k1lab/src/secp256k1lab/secp256k1.py",
        "reference/secp256k1lab/src/secp256k1lab/secp256k1.py",
    ),
    (
        "bip-0352/secp256k1lab/src/secp256k1lab/util.py",
        "reference/secp256k1lab/src/secp256k1lab/util.py",
    ),
)

V1_INPUT_TYPES = {
    "p2wpkh": 0x01,
    "p2tr": 0x02,
    "p2sh-p2wpkh": 0x03,
}
SUPPORTED_V1_INPUT_TYPES = set(V1_INPUT_TYPES)


class VectorError(Exception):
    pass


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _request(url: str) -> urllib.request.Request:
    return urllib.request.Request(url, headers={"User-Agent": "sp-differ/1"})


def fetch_bytes(url: str) -> bytes:
    with urllib.request.urlopen(_request(url)) as response:
        return response.read()


def fetch_json(url: str) -> Any:
    return json.loads(fetch_bytes(url).decode("utf-8"))


def resolve_branch_head() -> str:
    payload = fetch_json(UPSTREAM_BRANCH_API_URL)
    commit = payload.get("commit", {})
    sha = commit.get("sha")
    if not isinstance(sha, str) or not sha:
        raise VectorError("unable to resolve upstream branch head")
    return sha


def raw_url(ref: str, relative_path: str) -> str:
    return "https://raw.githubusercontent.com/bitcoin/bips/{}/{}".format(ref, relative_path)


def is_hex_string(value: Any, expected_len: Optional[int] = None) -> bool:
    if not isinstance(value, str):
        return False
    if expected_len is not None and len(value) != expected_len:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def is_compressed_pubkey_hex(value: Any) -> bool:
    return is_hex_string(value, 66) and value[:2] in ("02", "03")


def is_xonly_pubkey_hex(value: Any) -> bool:
    return is_hex_string(value, 64)


def validate_vectors(vectors: Any) -> List[Dict[str, Any]]:
    if not isinstance(vectors, list) or not vectors:
        raise VectorError("vector file must contain a non-empty list")

    for case_index, case in enumerate(vectors):
        if not isinstance(case, dict):
            raise VectorError("case {} is not an object".format(case_index))
        _require(isinstance(case.get("comment"), str), "case {} missing comment".format(case_index))
        _validate_send_entries(case_index, case.get("sending"))
        _validate_receive_entries(case_index, case.get("receiving"))

    return vectors


def _validate_send_entries(case_index: int, entries: Any) -> None:
    _require(isinstance(entries, list) and entries, "case {} missing sending entries".format(case_index))
    for send_index, entry in enumerate(entries):
        _require(isinstance(entry, dict), "case {} sending {} is not an object".format(case_index, send_index))
        given = entry.get("given")
        expected = entry.get("expected")
        _require(isinstance(given, dict), "case {} sending {} missing given".format(case_index, send_index))
        _require(
            isinstance(expected, dict),
            "case {} sending {} missing expected".format(case_index, send_index),
        )

        vin = given.get("vin")
        recipients = given.get("recipients")
        _require(isinstance(vin, list) and vin, "case {} sending {} missing vin".format(case_index, send_index))
        _require(
            isinstance(recipients, list) and recipients,
            "case {} sending {} missing recipients".format(case_index, send_index),
        )

        for vin_index, item in enumerate(vin):
            _validate_vin(case_index, send_index, vin_index, item)

        for recipient_index, item in enumerate(recipients):
            _validate_recipient(case_index, send_index, recipient_index, item)

        outputs = expected.get("outputs")
        shared_secrets = expected.get("shared_secrets")
        _require(
            isinstance(outputs, list),
            "case {} sending {} expected.outputs missing".format(case_index, send_index),
        )
        for group_index, output_group in enumerate(outputs):
            _require(
                isinstance(output_group, list),
                "case {} sending {} output group {} must be a list".format(case_index, send_index, group_index),
            )
            for output_index, output in enumerate(output_group):
                _require(
                    is_xonly_pubkey_hex(output),
                    "case {} sending {} output {}:{} invalid".format(
                        case_index, send_index, group_index, output_index
                    ),
                )

        _require(
            isinstance(shared_secrets, list),
            "case {} sending {} expected.shared_secrets missing".format(case_index, send_index),
        )
        for secret_index, secret in enumerate(shared_secrets):
            _require(
                secret is None or is_compressed_pubkey_hex(secret),
                "case {} sending {} shared secret {} invalid".format(case_index, send_index, secret_index),
            )

        input_private_key_sum = expected.get("input_private_key_sum")
        if input_private_key_sum is not None:
            _require(
                is_hex_string(input_private_key_sum, 64),
                "case {} sending {} input_private_key_sum invalid".format(case_index, send_index),
            )

        input_pub_keys = expected.get("input_pub_keys")
        _require(
            isinstance(input_pub_keys, list),
            "case {} sending {} expected.input_pub_keys missing".format(case_index, send_index),
        )
        for key_index, pubkey in enumerate(input_pub_keys):
            _require(
                is_compressed_pubkey_hex(pubkey),
                "case {} sending {} input_pub_keys[{}] invalid".format(case_index, send_index, key_index),
            )


def _validate_receive_entries(case_index: int, entries: Any) -> None:
    _require(isinstance(entries, list) and entries, "case {} missing receiving entries".format(case_index))
    for receive_index, entry in enumerate(entries):
        _require(isinstance(entry, dict), "case {} receiving {} is not an object".format(case_index, receive_index))
        given = entry.get("given")
        expected = entry.get("expected")
        _require(
            isinstance(given, dict),
            "case {} receiving {} missing given".format(case_index, receive_index),
        )
        _require(
            isinstance(expected, dict),
            "case {} receiving {} missing expected".format(case_index, receive_index),
        )

        vin = given.get("vin")
        outputs = given.get("outputs")
        key_material = given.get("key_material")
        labels = given.get("labels")

        _require(isinstance(vin, list) and vin, "case {} receiving {} missing vin".format(case_index, receive_index))
        _require(
            isinstance(outputs, list),
            "case {} receiving {} missing outputs".format(case_index, receive_index),
        )
        _require(
            isinstance(key_material, dict),
            "case {} receiving {} missing key_material".format(case_index, receive_index),
        )
        _require(isinstance(labels, list), "case {} receiving {} missing labels".format(case_index, receive_index))

        for vin_index, item in enumerate(vin):
            _validate_vin(case_index, receive_index, vin_index, item)

        for output_index, output in enumerate(outputs):
            _require(
                is_xonly_pubkey_hex(output),
                "case {} receiving {} output {} invalid".format(case_index, receive_index, output_index),
            )

        for label_index, label in enumerate(labels):
            _require(
                isinstance(label, int) and label >= 0,
                "case {} receiving {} label {} invalid".format(case_index, receive_index, label_index),
            )

        _require(
            is_hex_string(key_material.get("scan_priv_key"), 64),
            "case {} receiving {} scan_priv_key invalid".format(case_index, receive_index),
        )
        _require(
            is_hex_string(key_material.get("spend_priv_key"), 64),
            "case {} receiving {} spend_priv_key invalid".format(case_index, receive_index),
        )

        addresses = expected.get("addresses")
        _require(
            isinstance(addresses, list) and addresses,
            "case {} receiving {} expected.addresses missing".format(case_index, receive_index),
        )
        for address in addresses:
            _require(isinstance(address, str) and address, "case {} receiving {} address invalid".format(case_index, receive_index))

        expected_outputs = expected.get("outputs")
        if expected_outputs is not None:
            _require(
                isinstance(expected_outputs, list),
                "case {} receiving {} expected.outputs invalid".format(case_index, receive_index),
            )
            for output_index, output in enumerate(expected_outputs):
                _require(
                    isinstance(output, dict),
                    "case {} receiving {} expected output {} invalid".format(
                        case_index, receive_index, output_index
                    ),
                )
                _require(
                    is_xonly_pubkey_hex(output.get("pub_key")),
                    "case {} receiving {} expected pub_key invalid".format(case_index, receive_index),
                )
                _require(
                    is_hex_string(output.get("priv_key_tweak"), 64),
                    "case {} receiving {} expected priv_key_tweak invalid".format(case_index, receive_index),
                )
                _require(
                    is_hex_string(output.get("signature"), 128),
                    "case {} receiving {} expected signature invalid".format(case_index, receive_index),
                )

        for field in ("tweak", "shared_secret", "input_pub_key_sum"):
            value = expected.get(field)
            if value is not None:
                _require(
                    is_compressed_pubkey_hex(value),
                    "case {} receiving {} {} invalid".format(case_index, receive_index, field),
                )

        n_outputs = expected.get("n_outputs")
        if n_outputs is not None:
            _require(
                isinstance(n_outputs, int) and n_outputs >= 0,
                "case {} receiving {} n_outputs invalid".format(case_index, receive_index),
            )


def _validate_vin(case_index: int, entry_index: int, vin_index: int, item: Any) -> None:
    _require(isinstance(item, dict), "case {} entry {} vin {} invalid".format(case_index, entry_index, vin_index))
    _require(
        is_hex_string(item.get("txid"), 64),
        "case {} entry {} vin {} txid invalid".format(case_index, entry_index, vin_index),
    )
    _require(
        isinstance(item.get("vout"), int) and item["vout"] >= 0,
        "case {} entry {} vin {} vout invalid".format(case_index, entry_index, vin_index),
    )
    _require(
        is_hex_string(item.get("scriptSig")),
        "case {} entry {} vin {} scriptSig invalid".format(case_index, entry_index, vin_index),
    )
    _require(
        is_hex_string(item.get("txinwitness")),
        "case {} entry {} vin {} txinwitness invalid".format(case_index, entry_index, vin_index),
    )

    prevout = item.get("prevout")
    _require(
        isinstance(prevout, dict) and isinstance(prevout.get("scriptPubKey"), dict),
        "case {} entry {} vin {} prevout invalid".format(case_index, entry_index, vin_index),
    )
    _require(
        is_hex_string(prevout["scriptPubKey"].get("hex")),
        "case {} entry {} vin {} scriptPubKey invalid".format(case_index, entry_index, vin_index),
    )
    private_key = item.get("private_key")
    if private_key is not None:
        _require(
            is_hex_string(private_key, 64),
            "case {} entry {} vin {} private_key invalid".format(case_index, entry_index, vin_index),
        )


def _validate_recipient(case_index: int, send_index: int, recipient_index: int, item: Any) -> None:
    _require(
        isinstance(item, dict),
        "case {} sending {} recipient {} invalid".format(case_index, send_index, recipient_index),
    )
    _require(
        isinstance(item.get("address"), str) and item["address"],
        "case {} sending {} recipient {} address invalid".format(case_index, send_index, recipient_index),
    )
    _require(
        is_compressed_pubkey_hex(item.get("scan_pub_key")),
        "case {} sending {} recipient {} scan_pub_key invalid".format(case_index, send_index, recipient_index),
    )
    _require(
        is_compressed_pubkey_hex(item.get("spend_pub_key")),
        "case {} sending {} recipient {} spend_pub_key invalid".format(case_index, send_index, recipient_index),
    )
    if "count" in item:
        _require(
            isinstance(item["count"], int) and item["count"] > 0,
            "case {} sending {} recipient {} count invalid".format(case_index, send_index, recipient_index),
        )


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise VectorError(message)


def classify_input_type(vin: Dict[str, Any]) -> str:
    script_pubkey = vin["prevout"]["scriptPubKey"]["hex"]
    if script_pubkey.startswith("0014") and len(script_pubkey) == 44:
        return "p2wpkh"
    if script_pubkey.startswith("5120") and len(script_pubkey) == 68:
        return "p2tr"
    if script_pubkey.startswith("a914") and script_pubkey.endswith("87") and len(script_pubkey) == 46:
        return "p2sh-p2wpkh"
    if script_pubkey.startswith("76a914") and script_pubkey.endswith("88ac") and len(script_pubkey) == 50:
        return "p2pkh"
    return "other"


def project_send_entry_to_v1(case_index: int, send_index: int, case: Dict[str, Any], entry: Dict[str, Any]) -> Dict[str, Any]:
    given = entry["given"]
    expected = entry["expected"]
    input_types = [classify_input_type(vin) for vin in given["vin"]]
    unsupported_types = sorted({input_type for input_type in input_types if input_type not in SUPPORTED_V1_INPUT_TYPES})
    unique_recipient_keys = {
        (recipient["scan_pub_key"], recipient["spend_pub_key"]) for recipient in given["recipients"]
    }

    reasons: List[str] = []
    if unsupported_types:
        reasons.append("unsupported_input_type")
    if len(unique_recipient_keys) != 1:
        reasons.append("multiple_recipient_groups")

    output_count = sum(int(recipient.get("count", 1)) for recipient in given["recipients"])
    negative = sum(len(group) for group in expected["outputs"]) == 0
    scan_pubkey = given["recipients"][0]["scan_pub_key"]
    spend_pubkey = given["recipients"][0]["spend_pub_key"]

    return {
        "case_index": case_index,
        "send_index": send_index,
        "comment": case["comment"],
        "input_types": input_types,
        "unsupported_input_types": unsupported_types,
        "unique_recipient_group_count": len(unique_recipient_keys),
        "projectable": not reasons,
        "reasons": reasons,
        "output_count": output_count,
        "negative": negative,
        "scan_pub_key": scan_pubkey,
        "spend_pub_key": spend_pubkey,
        "expected": expected,
        "vin": given["vin"],
    }


def encode_case_v1_hex(projection: Dict[str, Any]) -> str:
    seed = (projection["case_index"] << 8) | projection["send_index"]
    flags = 0
    if projection["negative"]:
        flags |= 1 << 0
    flags |= 1 << 1  # private keys present

    payload = bytearray()
    payload.append(1)
    payload.extend(seed.to_bytes(8, "little"))
    payload.extend(flags.to_bytes(4, "little"))
    payload.extend(len(projection["vin"]).to_bytes(2, "little"))
    payload.extend(projection["output_count"].to_bytes(2, "little"))

    for vin, input_type in zip(projection["vin"], projection["input_types"]):
        payload.extend(deserialize_txid(vin["txid"]))
        payload.extend(int(vin["vout"]).to_bytes(4, "little"))
        payload.append(V1_INPUT_TYPES[input_type])
        payload.extend(bytes.fromhex(vin["private_key"]))

    payload.extend(bytes.fromhex(projection["scan_pub_key"]))
    payload.extend(bytes.fromhex(projection["spend_pub_key"]))
    payload.extend((0).to_bytes(2, "little"))

    return payload.hex()


def deserialize_txid(txid: str) -> bytes:
    return bytes.fromhex(txid)[::-1]


def summarize_vectors(vectors: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    cases = list(vectors)
    sending_entries = sum(len(case["sending"]) for case in cases)
    receiving_entries = sum(len(case["receiving"]) for case in cases)
    projections = [
        project_send_entry_to_v1(case_index, send_index, case, entry)
        for case_index, case in enumerate(cases)
        for send_index, entry in enumerate(case["sending"])
    ]

    summary = {
        "case_count": len(cases),
        "sending_entry_count": sending_entries,
        "receiving_entry_count": receiving_entries,
        "projectable_sending_entries": sum(1 for item in projections if item["projectable"]),
        "blocked_sending_entries": sum(1 for item in projections if not item["projectable"]),
        "projection_reason_counts": count_projection_reasons(projections),
    }
    return summary


def count_projection_reasons(projections: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for projection in projections:
        for reason in projection["reasons"]:
            counts[reason] = counts.get(reason, 0) + 1
    return counts


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
