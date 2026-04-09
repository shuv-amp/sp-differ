use bech32::{Bech32m, ByteIterExt, Fe32, Fe32IterExt, Hrp};
use bip352::input_public_key;
use bip352::{ScanSecretKey, SharedSecret, SpendPublicKey};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{Parity, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Txid, Witness};
use hex::{decode as hex_decode, encode as hex_encode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::{self, Read};
use std::str::FromStr;

pub const SEMANTIC_WORKER_API_VERSION: u32 = 1;
const SEMANTIC_CONTRACT_VERSION: u32 = 1;
const SEMANTIC_ADAPTER_REQUEST_VERSION: u32 = 1;
const CASE_FORMAT_VERSION: u32 = 2;
const K_MAX: usize = 2323;

type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Deserialize, Serialize)]
struct Source {
    upstream_commit: String,
    case_index: i64,
    entry_index: i64,
    kind: String,
    comment: String,
    id: String,
}

#[derive(Clone, Deserialize)]
#[allow(dead_code)]
struct InputRequest {
    outpoint_txid: String,
    outpoint_vout: u32,
    input_type: String,
    prevout_script_pubkey: Option<String>,
    script_sig: Option<String>,
    txinwitness: Option<String>,
    txinwitness_stack: Vec<String>,
    privkey: Option<String>,
    pubkey: Option<String>,
}

#[derive(Clone, Deserialize)]
struct RecipientGroupRequest {
    scan_pubkey: String,
    spend_pubkey: String,
    count: u16,
}

#[derive(Clone, Deserialize)]
struct ReceiverKeysRequest {
    scan_privkey: String,
    spend_privkey: String,
}

#[derive(Clone, Deserialize)]
struct ExpectationHints {
    detailed_outputs_required: Option<bool>,
}

#[derive(Clone, Deserialize)]
struct AdapterRequest {
    semantic_adapter_request_version: u32,
    case_format_version: u32,
    kind: String,
    network: String,
    silent_payment_version: u8,
    source: Source,
    inputs: Vec<InputRequest>,
    expectation_hints: Option<ExpectationHints>,
    recipient_groups: Option<Vec<RecipientGroupRequest>>,
    outputs_to_scan: Option<Vec<String>>,
    receiver_keys: Option<ReceiverKeysRequest>,
    labels: Option<Vec<u32>>,
}

#[derive(Serialize)]
struct SharedSecretEntry {
    scan_pubkey: String,
    shared_secret: Option<String>,
}

#[derive(Serialize)]
struct FoundOutput {
    pub_key: String,
    priv_key_tweak: String,
}

struct EligibleSendInput {
    public_key: PublicKey,
    privkey: SecretKey,
    is_taproot: bool,
}

struct EligibleReceiveInput {
    public_key: PublicKey,
}

struct ScanGroup {
    scan_pubkey_hex: String,
    scan_pubkey: PublicKey,
    spend_pubkeys: Vec<PublicKey>,
}

struct LabelSpendKey {
    spend_pubkey: SpendPublicKey,
    tweak: Scalar,
}

fn main() {
    if let Err(message) = run() {
        eprintln!("error: {}", message);
        std::process::exit(2);
    }
}

fn run() -> Result<()> {
    let mut stdin = String::new();
    io::stdin()
        .read_to_string(&mut stdin)
        .map_err(|e| e.to_string())?;
    let response = run_request_json(&stdin)?;
    println!("{}", response);
    Ok(())
}

pub fn run_request_json(input: &str) -> std::result::Result<String, String> {
    let request: AdapterRequest =
        serde_json::from_str(input).map_err(|e| format!("invalid request JSON: {}", e))?;
    validate_request(&request)?;
    let response = match request.kind.as_str() {
        "send" => derive_send_semantics(&request)?,
        "receive" => derive_receive_semantics(&request)?,
        _ => return Err("unknown kind".to_owned()),
    };
    serde_json::to_string(&response).map_err(|e| e.to_string())
}

fn validate_request(request: &AdapterRequest) -> Result<()> {
    if request.semantic_adapter_request_version != SEMANTIC_ADAPTER_REQUEST_VERSION {
        return Err("unsupported semantic adapter request version".to_owned());
    }
    if request.case_format_version != CASE_FORMAT_VERSION {
        return Err("case_format_version must be 2".to_owned());
    }
    if request.silent_payment_version != 0 {
        return Err("silent_payment_version must be 0".to_owned());
    }
    if request.source.kind != request.kind {
        return Err("source.kind mismatch".to_owned());
    }
    if request.kind == "send"
        && request
            .recipient_groups
            .as_ref()
            .map(|groups| groups.is_empty())
            .unwrap_or(true)
    {
        return Err("missing recipient_groups".to_owned());
    }
    if request.kind == "receive" {
        if request.outputs_to_scan.is_none() {
            return Err("missing outputs_to_scan".to_owned());
        }
        if request.receiver_keys.is_none() {
            return Err("missing receiver_keys".to_owned());
        }
        if request.labels.is_none() {
            return Err("missing labels".to_owned());
        }
    }
    Ok(())
}

fn derive_send_semantics(request: &AdapterRequest) -> Result<Value> {
    let secp = Secp256k1::new();
    let groups = build_scan_groups(
        request
            .recipient_groups
            .as_ref()
            .ok_or_else(|| "missing recipient_groups".to_owned())?,
    )?;
    let empty_shared_secrets = groups
        .iter()
        .map(|group| SharedSecretEntry {
            scan_pubkey: group.scan_pubkey_hex.clone(),
            shared_secret: None,
        })
        .collect::<Vec<_>>();
    let eligible = collect_send_inputs(request)?;
    let input_pubkeys = eligible
        .iter()
        .map(|entry| hex_encode(entry.public_key.serialize()))
        .collect::<Vec<_>>();

    if eligible.is_empty() {
        return Ok(json!({
            "semantic_contract_version": SEMANTIC_CONTRACT_VERSION,
            "case_format_version": CASE_FORMAT_VERSION,
            "kind": "send",
            "source": request.source,
            "semantic_status": "no_eligible_inputs",
            "input_pubkeys": [],
            "input_hash": Value::Null,
            "input_private_key_sum": Value::Null,
            "sender_shared_secrets": empty_shared_secrets,
            "acceptable_output_sets": [[]],
            "output_count_options": [0],
            "notes": [],
        }));
    }

    let input_keys = eligible
        .iter()
        .map(|entry| (entry.privkey, entry.is_taproot))
        .collect::<Vec<_>>();
    let a_sum = match sum_input_secret_keys(&input_keys, &secp) {
        Ok(value) => value,
        Err(status) if status == "zero_scalar" => {
            return Ok(json!({
                "semantic_contract_version": SEMANTIC_CONTRACT_VERSION,
                "case_format_version": CASE_FORMAT_VERSION,
                "kind": "send",
                "source": request.source,
                "semantic_status": "zero_scalar",
                "input_pubkeys": input_pubkeys,
                "input_hash": Value::Null,
                "input_private_key_sum": "0000000000000000000000000000000000000000000000000000000000000000",
                "sender_shared_secrets": empty_shared_secrets,
                "acceptable_output_sets": [[]],
                "output_count_options": [0],
                "notes": [],
            }));
        }
        Err(status) => return Err(status),
    };

    let a_sum_pubkey = a_sum.public_key(&secp);
    let input_hash_bytes = calculate_input_hash(&request.inputs, &a_sum_pubkey)?;
    let input_hash_scalar = Scalar::from_be_bytes(input_hash_bytes).map_err(|e| e.to_string())?;
    if scan_group_recipient_limit_exceeded(
        request
            .recipient_groups
            .as_ref()
            .ok_or_else(|| "missing recipient_groups".to_owned())?,
    ) {
        return Ok(json!({
            "semantic_contract_version": SEMANTIC_CONTRACT_VERSION,
            "case_format_version": CASE_FORMAT_VERSION,
            "kind": "send",
            "source": request.source,
            "semantic_status": "recipient_limit_exceeded",
            "input_pubkeys": input_pubkeys,
            "input_hash": hex_encode(input_hash_bytes),
            "input_private_key_sum": hex_encode(a_sum.secret_bytes()),
            "sender_shared_secrets": empty_shared_secrets,
            "acceptable_output_sets": [[]],
            "output_count_options": [0],
            "notes": ["per_group_recipient_limit_exceeded"],
        }));
    }

    let sender_shared_secrets =
        build_sender_shared_secrets(&groups, &a_sum, input_hash_scalar, &secp)?;
    let output_list = derive_sender_outputs(&groups, &a_sum, input_hash_scalar, &secp)?;

    Ok(json!({
        "semantic_contract_version": SEMANTIC_CONTRACT_VERSION,
        "case_format_version": CASE_FORMAT_VERSION,
        "kind": "send",
        "source": request.source,
        "semantic_status": "ok",
        "input_pubkeys": input_pubkeys,
        "input_hash": hex_encode(input_hash_bytes),
        "input_private_key_sum": hex_encode(a_sum.secret_bytes()),
        "sender_shared_secrets": sender_shared_secrets,
        "acceptable_output_sets": [output_list.clone()],
        "output_count_options": [output_list.len()],
        "notes": [],
    }))
}

fn derive_receive_semantics(request: &AdapterRequest) -> Result<Value> {
    let secp = Secp256k1::new();
    let eligible = collect_receive_inputs(request)?;
    let input_pubkeys = eligible
        .iter()
        .map(|entry| hex_encode(entry.public_key.serialize()))
        .collect::<Vec<_>>();
    let receiver_keys = request
        .receiver_keys
        .as_ref()
        .ok_or_else(|| "missing receiver_keys".to_owned())?;
    let b_scan =
        SecretKey::from_slice(&hex_decode(&receiver_keys.scan_privkey).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let b_spend = SecretKey::from_slice(
        &hex_decode(&receiver_keys.spend_privkey).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let scan_secret = ScanSecretKey::new(b_scan);
    let spend_pubkey = b_spend.public_key(&secp);
    let spend_pubkey_wrapped = SpendPublicKey::new(spend_pubkey);
    let labels = request.labels.clone().unwrap_or_default();
    let receiving_addresses = build_receiving_addresses(
        &scan_secret,
        spend_pubkey_wrapped,
        &labels,
        request.network.as_str(),
    )?;

    if eligible.is_empty() {
        return Ok(json!({
            "semantic_contract_version": SEMANTIC_CONTRACT_VERSION,
            "case_format_version": CASE_FORMAT_VERSION,
            "kind": "receive",
            "source": request.source,
            "semantic_status": "no_eligible_inputs",
            "input_pubkeys": [],
            "input_hash": Value::Null,
            "receiving_addresses": receiving_addresses,
            "input_pubkey_sum": Value::Null,
            "tweak": Value::Null,
            "shared_secret": Value::Null,
            "detailed_outputs_available": true,
            "found_output_count": 0,
            "found_outputs": [],
            "notes": [],
        }));
    }

    let eligible_pubkeys = eligible
        .iter()
        .map(|entry| entry.public_key)
        .collect::<Vec<_>>();
    let eligible_refs = eligible_pubkeys.iter().collect::<Vec<_>>();
    let a_sum = PublicKey::combine_keys(&eligible_refs).map_err(|_| "point_at_infinity".to_owned());
    let a_sum = match a_sum {
        Ok(value) => value,
        Err(status) => {
            return Ok(json!({
                "semantic_contract_version": SEMANTIC_CONTRACT_VERSION,
                "case_format_version": CASE_FORMAT_VERSION,
                "kind": "receive",
                "source": request.source,
                "semantic_status": status,
                "input_pubkeys": input_pubkeys,
                "input_hash": Value::Null,
                "receiving_addresses": receiving_addresses,
                "input_pubkey_sum": Value::Null,
                "tweak": Value::Null,
                "shared_secret": Value::Null,
                "detailed_outputs_available": true,
                "found_output_count": 0,
                "found_outputs": [],
                "notes": [],
            }));
        }
    };

    let input_hash_bytes = calculate_input_hash(&request.inputs, &a_sum)?;
    let input_hash_scalar = Scalar::from_be_bytes(input_hash_bytes).map_err(|e| e.to_string())?;
    let tweak = a_sum
        .mul_tweak(&secp, &input_hash_scalar)
        .map_err(|e| format!("failed to derive tweak point: {}", e))?;
    let shared_secret = SharedSecret::new(input_hash_scalar, a_sum, b_scan, &secp)
        .map_err(|e| format!("failed to derive receive shared secret: {}", e))?;
    let shared_secret_hex = hex_encode(
        a_sum
            .mul_tweak(&secp, &Scalar::from(b_scan))
            .map_err(|e| format!("failed to derive receive shared secret: {}", e))?
            .mul_tweak(&secp, &input_hash_scalar)
            .map_err(|e| format!("failed to derive receive shared secret: {}", e))?
            .serialize(),
    );
    let label_spend_keys =
        build_label_spend_keys(&scan_secret, spend_pubkey_wrapped, &labels, &secp)?;
    let detailed_outputs_required = request
        .expectation_hints
        .as_ref()
        .and_then(|hints| hints.detailed_outputs_required)
        .unwrap_or(true);

    let (found_output_count, found_outputs, notes) = scan_outputs(
        &shared_secret,
        spend_pubkey_wrapped,
        &label_spend_keys,
        request.outputs_to_scan.as_deref().unwrap_or(&[]),
        !detailed_outputs_required,
        &secp,
    )?;

    Ok(json!({
        "semantic_contract_version": SEMANTIC_CONTRACT_VERSION,
        "case_format_version": CASE_FORMAT_VERSION,
        "kind": "receive",
        "source": request.source,
        "semantic_status": "ok",
        "input_pubkeys": input_pubkeys,
        "input_hash": hex_encode(input_hash_bytes),
        "receiving_addresses": receiving_addresses,
        "input_pubkey_sum": hex_encode(a_sum.serialize()),
        "tweak": hex_encode(tweak.serialize()),
        "shared_secret": shared_secret_hex,
        "detailed_outputs_available": detailed_outputs_required,
        "found_output_count": found_output_count,
        "found_outputs": if detailed_outputs_required { found_outputs } else { Vec::<FoundOutput>::new() },
        "notes": notes,
    }))
}

fn collect_send_inputs(request: &AdapterRequest) -> Result<Vec<EligibleSendInput>> {
    let mut eligible = Vec::new();
    for input in &request.inputs {
        let (txin, prevout) = build_txin_and_prevout(input)?;
        let Some(public_key) = input_public_key(&prevout.script_pubkey, &txin) else {
            continue;
        };
        let privkey_hex = input
            .privkey
            .as_ref()
            .ok_or_else(|| "eligible sender input is missing privkey".to_owned())?;
        let privkey = SecretKey::from_slice(&hex_decode(privkey_hex).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        eligible.push(EligibleSendInput {
            public_key,
            privkey,
            is_taproot: prevout.script_pubkey.is_p2tr(),
        });
    }
    Ok(eligible)
}

fn collect_receive_inputs(request: &AdapterRequest) -> Result<Vec<EligibleReceiveInput>> {
    let mut eligible = Vec::new();
    for input in &request.inputs {
        let (txin, prevout) = build_txin_and_prevout(input)?;
        let Some(public_key) = input_public_key(&prevout.script_pubkey, &txin) else {
            continue;
        };
        eligible.push(EligibleReceiveInput { public_key });
    }
    Ok(eligible)
}

fn build_txin_and_prevout(input: &InputRequest) -> Result<(TxIn, TxOut)> {
    let txid = Txid::from_str(&input.outpoint_txid).map_err(|e| e.to_string())?;
    let script_sig = ScriptBuf::from_bytes(decode_optional_hex(input.script_sig.as_ref())?);
    let witness = decode_witness_stack(&input.txinwitness_stack)?;
    let prevout_script_pubkey = ScriptBuf::from_bytes(decode_required_hex(
        input.prevout_script_pubkey.as_ref(),
        "missing prevout_script_pubkey",
    )?);
    let txin = TxIn {
        previous_output: OutPoint {
            txid,
            vout: input.outpoint_vout,
        },
        script_sig,
        witness,
        sequence: Sequence::MAX,
    };
    let prevout = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: prevout_script_pubkey,
    };
    Ok((txin, prevout))
}

fn decode_witness_stack(values: &[String]) -> Result<Witness> {
    let items = values
        .iter()
        .map(|value| hex_decode(value).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>>>()?;
    let refs = items.iter().map(|item| item.as_slice()).collect::<Vec<_>>();
    Ok(Witness::from_slice(&refs))
}

fn decode_optional_hex(value: Option<&String>) -> Result<Vec<u8>> {
    match value {
        Some(item) => hex_decode(item).map_err(|e| e.to_string()),
        None => Ok(Vec::new()),
    }
}

fn decode_required_hex(value: Option<&String>, message: &str) -> Result<Vec<u8>> {
    match value {
        Some(item) => hex_decode(item).map_err(|e| e.to_string()),
        None => Err(message.to_owned()),
    }
}

fn build_scan_groups(groups: &[RecipientGroupRequest]) -> Result<Vec<ScanGroup>> {
    let mut ordered = Vec::new();
    let mut index_by_scan = HashMap::new();
    for group in groups {
        let scan_pubkey =
            PublicKey::from_slice(&hex_decode(&group.scan_pubkey).map_err(|e| e.to_string())?)
                .map_err(|e| format!("failed to decode scan pubkey: {}", e))?;
        let spend_pubkey =
            PublicKey::from_slice(&hex_decode(&group.spend_pubkey).map_err(|e| e.to_string())?)
                .map_err(|e| format!("failed to decode spend pubkey: {}", e))?;
        let index = match index_by_scan.get(&group.scan_pubkey) {
            Some(existing) => *existing,
            None => {
                let next = ordered.len();
                ordered.push(ScanGroup {
                    scan_pubkey_hex: group.scan_pubkey.clone(),
                    scan_pubkey,
                    spend_pubkeys: Vec::new(),
                });
                index_by_scan.insert(group.scan_pubkey.clone(), next);
                next
            }
        };
        for _ in 0..usize::from(group.count) {
            ordered[index].spend_pubkeys.push(spend_pubkey);
        }
    }
    Ok(ordered)
}

fn scan_group_recipient_limit_exceeded(groups: &[RecipientGroupRequest]) -> bool {
    let mut counts = HashMap::new();
    for group in groups {
        let count = counts.entry(group.scan_pubkey.as_str()).or_insert(0usize);
        *count += usize::from(group.count);
        if *count > K_MAX {
            return true;
        }
    }
    false
}

fn calculate_input_hash(
    inputs: &[InputRequest],
    sum_input_pubkeys: &PublicKey,
) -> Result<[u8; 32]> {
    if inputs.is_empty() {
        return Err("no outpoints provided".to_owned());
    }

    let mut serialized = inputs
        .iter()
        .map(|input| {
            let mut txid_bytes = hex_decode(&input.outpoint_txid).map_err(|e| e.to_string())?;
            if txid_bytes.len() != 32 {
                return Err(format!("invalid txid length: {}", input.outpoint_txid));
            }
            txid_bytes.reverse();
            let mut outpoint = [0u8; 36];
            outpoint[..32].copy_from_slice(&txid_bytes);
            outpoint[32..].copy_from_slice(&input.outpoint_vout.to_le_bytes());
            Ok(outpoint)
        })
        .collect::<Result<Vec<_>>>()?;
    serialized.sort_unstable();

    let mut message = Vec::with_capacity(69);
    message.extend_from_slice(&serialized[0]);
    message.extend_from_slice(&sum_input_pubkeys.serialize());
    Ok(tagged_hash("BIP0352/Inputs", &message))
}

fn derive_sender_outputs(
    groups: &[ScanGroup],
    a_sum: &SecretKey,
    input_hash: Scalar,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> Result<Vec<String>> {
    let mut output_set = BTreeSet::new();
    for group in groups {
        let shared_secret = SharedSecret::new(input_hash, group.scan_pubkey, *a_sum, secp)
            .map_err(|e| format!("failed to derive sender shared secret: {}", e))?;
        for (index, spend_pubkey) in group.spend_pubkeys.iter().enumerate() {
            let (output, _) = shared_secret.destination_public_key(
                SpendPublicKey::new(*spend_pubkey),
                index as u32,
                secp,
            );
            output_set.insert(hex_encode(output.x_only_public_key().0.serialize()));
        }
    }
    Ok(output_set.into_iter().collect())
}

fn build_sender_shared_secrets(
    groups: &[ScanGroup],
    a_sum: &SecretKey,
    input_hash: Scalar,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> Result<Vec<SharedSecretEntry>> {
    let mut entries = Vec::new();
    for group in groups {
        let shared_secret = group
            .scan_pubkey
            .mul_tweak(secp, &Scalar::from(*a_sum))
            .map_err(|e| format!("failed to derive sender shared secret: {}", e))?
            .mul_tweak(secp, &input_hash)
            .map_err(|e| format!("failed to derive sender shared secret: {}", e))?;
        entries.push(SharedSecretEntry {
            scan_pubkey: group.scan_pubkey_hex.clone(),
            shared_secret: Some(hex_encode(shared_secret.serialize())),
        });
    }
    entries.sort_by(|left, right| left.scan_pubkey.cmp(&right.scan_pubkey));
    Ok(entries)
}

fn build_receiving_addresses(
    scan_secret: &ScanSecretKey,
    spend_pubkey: SpendPublicKey,
    labels: &[u32],
    network_name: &str,
) -> Result<Vec<String>> {
    let secp = Secp256k1::new();
    let testing = is_testing_network(network_name)?;
    let scan_pubkey = scan_secret.public_key(&secp).into_public_key();
    let spend_pubkey_raw =
        PublicKey::from_slice(&spend_pubkey.serialize()).map_err(|e| e.to_string())?;
    let mut addresses = vec![encode_silent_payment_address(
        scan_pubkey,
        spend_pubkey_raw,
        testing,
    )];
    for label in labels {
        let tweak = label_scalar(scan_secret.to_secret_key(), *label)?;
        let labeled_spend = spend_pubkey_raw
            .add_exp_tweak(&secp, &tweak)
            .map_err(|e| format!("failed to derive labeled spend pubkey {}: {}", label, e))?;
        addresses.push(encode_silent_payment_address(
            scan_pubkey,
            labeled_spend,
            testing,
        ));
    }
    Ok(addresses)
}

fn is_testing_network(value: &str) -> Result<bool> {
    match value {
        "mainnet" => Ok(false),
        "testnet" | "regtest" => Ok(true),
        _ => Err(format!("unsupported network: {}", value)),
    }
}

fn build_label_spend_keys(
    scan_secret: &ScanSecretKey,
    spend_pubkey: SpendPublicKey,
    labels: &[u32],
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> Result<Vec<LabelSpendKey>> {
    let mut entries = Vec::new();
    let spend_pubkey_raw =
        PublicKey::from_slice(&spend_pubkey.serialize()).map_err(|e| e.to_string())?;
    for label in labels {
        let tweak = label_scalar(scan_secret.to_secret_key(), *label)?;
        let labeled_spend = spend_pubkey_raw
            .add_exp_tweak(secp, &tweak)
            .map_err(|e| format!("failed to apply label {}: {}", label, e))?;
        entries.push(LabelSpendKey {
            spend_pubkey: SpendPublicKey::new(labeled_spend),
            tweak,
        });
    }
    Ok(entries)
}

fn scan_outputs(
    shared_secret: &SharedSecret,
    spend_pubkey: SpendPublicKey,
    label_spend_keys: &[LabelSpendKey],
    outputs_to_scan: &[String],
    count_only: bool,
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> Result<(usize, Vec<FoundOutput>, Vec<String>)> {
    let mut remaining = HashSet::new();
    for output in outputs_to_scan {
        let bytes = hex_decode(output).map_err(|e| e.to_string())?;
        let pubkey =
            XOnlyPublicKey::from_slice(&bytes).map_err(|_| "malformed public key".to_owned())?;
        remaining.insert(hex_encode(pubkey.serialize()));
    }
    let mut found_outputs = Vec::new();
    let mut found_count = 0usize;
    let limit = K_MAX as u32;

    let mut k = 0u32;
    while k < limit {
        let (base_output, base_tweak) = shared_secret.destination_public_key(spend_pubkey, k, secp);
        let base_xonly = hex_encode(base_output.x_only_public_key().0.serialize());
        if remaining.remove(&base_xonly) {
            found_count += 1;
            if !count_only {
                found_outputs.push(FoundOutput {
                    pub_key: base_xonly,
                    priv_key_tweak: hex_encode(base_tweak.to_be_bytes()),
                });
            }
            k += 1;
            continue;
        }

        let mut matched = false;
        for label_entry in label_spend_keys {
            let (output, tweak) =
                shared_secret.destination_public_key(label_entry.spend_pubkey, k, secp);
            let output_xonly = hex_encode(output.x_only_public_key().0.serialize());
            if !remaining.remove(&output_xonly) {
                continue;
            }
            let full_tweak = combine_scalars(&[tweak, label_entry.tweak])?;
            found_count += 1;
            if !count_only {
                found_outputs.push(FoundOutput {
                    pub_key: output_xonly,
                    priv_key_tweak: hex_encode(full_tweak.to_be_bytes()),
                });
            }
            matched = true;
            break;
        }

        if !matched {
            break;
        }
        k += 1;
    }

    let mut notes = Vec::new();
    if outputs_to_scan.len() > K_MAX && found_count == K_MAX {
        notes.push("scan_limit_reached".to_owned());
    }
    if count_only {
        notes.push("count_only_expectation".to_owned());
    }
    Ok((found_count, found_outputs, notes))
}

fn sum_input_secret_keys(
    input_keys: &[(SecretKey, bool)],
    secp: &Secp256k1<bitcoin::secp256k1::All>,
) -> std::result::Result<SecretKey, String> {
    if input_keys.is_empty() {
        return Err("no_eligible_inputs".to_owned());
    }
    let mut normalized = Vec::with_capacity(input_keys.len());
    for (key, is_taproot) in input_keys {
        let (_, parity) = key.x_only_public_key(secp);
        if *is_taproot && parity == Parity::Odd {
            normalized.push(key.negate());
        } else {
            normalized.push(*key);
        }
    }
    let mut iter = normalized.into_iter();
    let mut acc = iter.next().ok_or_else(|| "no_eligible_inputs".to_owned())?;
    for key in iter {
        acc = acc
            .add_tweak(&Scalar::from(key))
            .map_err(|_| "zero_scalar".to_owned())?;
    }
    Ok(acc)
}

fn combine_scalars(terms: &[Scalar]) -> Result<Scalar> {
    let mut acc: Option<SecretKey> = None;
    for term in terms {
        if *term == Scalar::ZERO {
            continue;
        }
        let secret = SecretKey::from_slice(&term.to_be_bytes()).map_err(|e| e.to_string())?;
        acc = Some(match acc {
            None => secret,
            Some(existing) => existing
                .add_tweak(&Scalar::from(secret))
                .map_err(|e| e.to_string())?,
        });
    }
    Ok(match acc {
        Some(secret) => Scalar::from(secret),
        None => Scalar::ZERO,
    })
}

fn label_scalar(scan_secret: SecretKey, label: u32) -> Result<Scalar> {
    let tweak_bytes = tagged_hash(
        "BIP0352/Label",
        &[&scan_secret.secret_bytes()[..], &label.to_be_bytes()[..]].concat(),
    );
    Scalar::from_be_bytes(tweak_bytes).map_err(|e| e.to_string())
}

fn tagged_hash(tag: &str, message: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    engine.input(message);
    sha256::Hash::from_engine(engine).to_byte_array()
}

fn encode_silent_payment_address(
    scan_pubkey: PublicKey,
    spend_pubkey: PublicKey,
    testing: bool,
) -> String {
    let hrp = if testing {
        Hrp::parse_unchecked("tsp")
    } else {
        Hrp::parse_unchecked("sp")
    };
    scan_pubkey
        .serialize()
        .iter()
        .chain(spend_pubkey.serialize().iter())
        .copied()
        .bytes_to_fes()
        .with_checksum::<Bech32m>(&hrp)
        .with_witness_version(Fe32::Q)
        .chars()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_value(request_json: &str) -> Value {
        serde_json::from_str(&run_request_json(request_json).expect("request should succeed"))
            .expect("actual response should be valid JSON")
    }

    #[test]
    fn grouped_recipient_limit_counts_shared_scan_pubkeys() {
        let groups = vec![
            RecipientGroupRequest {
                scan_pubkey: "scan-a".to_owned(),
                spend_pubkey: "spend-a".to_owned(),
                count: 2000,
            },
            RecipientGroupRequest {
                scan_pubkey: "scan-a".to_owned(),
                spend_pubkey: "spend-b".to_owned(),
                count: 324,
            },
            RecipientGroupRequest {
                scan_pubkey: "scan-b".to_owned(),
                spend_pubkey: "spend-c".to_owned(),
                count: 10,
            },
        ];
        assert!(scan_group_recipient_limit_exceeded(&groups));
    }

    #[test]
    fn send_input_hash_uses_privkey_sum_not_revealed_input_pubkeys() {
        let actual_value = run_value(include_str!(
            "../../../tests/fixtures/send_input_hash_uses_privkey_sum.request.json"
        ));
        assert_eq!(
            actual_value["input_hash"],
            Value::String(
                "2c1a59f99aa869070068150bb4a394c4bed7aebba055b5408b7c503b2649932c".to_owned()
            ),
        );
        assert_eq!(
            actual_value["sender_shared_secrets"][0]["shared_secret"],
            Value::String(
                "02c8f4ce9acc0685424176e150b74244699304f994be15f4d41f49a6c1319826fe".to_owned()
            ),
        );
    }

    #[test]
    fn receive_rejects_malformed_output_pubkeys() {
        let request = r#"{
          "semantic_adapter_request_version": 1,
          "case_format_version": 2,
          "kind": "receive",
          "network": "mainnet",
          "silent_payment_version": 0,
          "source": {
            "upstream_commit": "test",
            "case_index": 0,
            "entry_index": 0,
            "kind": "receive",
            "comment": "test",
            "id": "test_receive_rejects_malformed_output_pubkeys"
          },
          "inputs": [
            {
              "input_type": "p2wpkh",
              "outpoint_txid": "3a286147b25e16ae80aff406f2673c6e565418c40f45c071245cdebc8a94174e",
              "outpoint_vout": 1,
              "prevout_script_pubkey": "00149860538b5575962776ed0814ae222c7d60c72d7b",
              "privkey": null,
              "pubkey": null,
              "script_sig": "",
              "txinwitness": "0247304402204586a68e1d97dd3c6928e3622799859f8c3b20c3c670cf654cc905c9be29fdb7022043fbcde1689f3f4045e8816caf6163624bd19e62e4565bc99f95c533e599782c012103557ef3e55b0a52489b4454c1169e06bdea43687a69c1f190eb50781644ab6975",
              "txinwitness_stack": [
                "304402204586a68e1d97dd3c6928e3622799859f8c3b20c3c670cf654cc905c9be29fdb7022043fbcde1689f3f4045e8816caf6163624bd19e62e4565bc99f95c533e599782c01",
                "03557ef3e55b0a52489b4454c1169e06bdea43687a69c1f190eb50781644ab6975"
              ]
            }
          ],
          "outputs_to_scan": [
            "0000000000000000000000000000000000000000000000000000000000000000"
          ],
          "receiver_keys": {
            "scan_privkey": "0000000000000000000000000000000000000000000000000000000000000002",
            "spend_privkey": "0000000000000000000000000000000000000000000000000000000000000001"
          },
          "labels": []
        }"#;
        let error = run_request_json(request).expect_err("request should fail");
        assert_eq!(error, "malformed public key");
    }

    #[test]
    fn receive_point_at_infinity_short_circuits_before_scanning_outputs() {
        let actual_value = run_value(include_str!(
            "../../../tests/fixtures/receive_point_at_infinity_ignores_malformed_outputs.request.json"
        ));
        assert_eq!(
            actual_value["semantic_status"],
            Value::String("point_at_infinity".to_owned()),
        );
        assert_eq!(actual_value["input_hash"], Value::Null);
        assert_eq!(actual_value["shared_secret"], Value::Null);
    }
}
