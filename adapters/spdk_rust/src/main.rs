use bitcoin_hashes::{sha256, Hash, HashEngine};
use hex::{decode as hex_decode, encode as hex_encode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use silentpayments::receiving::{Label, Receiver};
use silentpayments::sending::generate_recipient_pubkeys;
use silentpayments::utils::receiving::{
    calculate_ecdh_shared_secret as calculate_receive_shared_secret, calculate_tweak_data,
    get_pubkey_from_input, is_p2tr,
};
use silentpayments::utils::sending::{
    calculate_ecdh_shared_secret as calculate_send_shared_secret, calculate_partial_secret,
};
use silentpayments::{secp256k1, Network, SilentPaymentAddress};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::{self, Read};

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
    let secp = secp256k1::Secp256k1::new();
    let outpoints_data = build_outpoints(request)?;
    let mut input_pubkeys = Vec::new();
    let mut eligible_keys = Vec::new();
    for input in &request.inputs {
        if let Some(pubkey) = extract_pubkey(input)? {
            input_pubkeys.push(hex_encode(pubkey.serialize()));
            let privkey_hex = input
                .privkey
                .as_ref()
                .ok_or_else(|| "eligible sender input is missing privkey".to_owned())?;
            let privkey = secp256k1::SecretKey::from_slice(
                &hex_decode(privkey_hex).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            let script_pubkey_hex = input
                .prevout_script_pubkey
                .as_ref()
                .ok_or_else(|| "missing prevout_script_pubkey".to_owned())?;
            let prevout_script_pubkey =
                hex_decode(script_pubkey_hex).map_err(|e| e.to_string())?;
            eligible_keys.push((privkey, is_p2tr(&prevout_script_pubkey)));
        }
    }

    let groups = request
        .recipient_groups
        .as_ref()
        .ok_or_else(|| "missing recipient_groups".to_owned())?;
    let shared_secret_entries = unique_scan_pubkeys(groups)
        .into_iter()
        .map(|scan_pubkey| SharedSecretEntry {
            scan_pubkey,
            shared_secret: None,
        })
        .collect::<Vec<_>>();

    if input_pubkeys.is_empty() {
        return Ok(json!({
            "semantic_contract_version": SEMANTIC_CONTRACT_VERSION,
            "case_format_version": CASE_FORMAT_VERSION,
            "kind": "send",
            "source": request.source,
            "semantic_status": "no_eligible_inputs",
            "input_pubkeys": [],
            "input_hash": Value::Null,
            "input_private_key_sum": Value::Null,
            "sender_shared_secrets": shared_secret_entries,
            "acceptable_output_sets": [[]],
            "output_count_options": [0],
            "notes": [],
        }));
    }

    let a_sum = match sum_input_secret_keys(&eligible_keys, &secp) {
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
                "sender_shared_secrets": shared_secret_entries,
                "acceptable_output_sets": [[]],
                "output_count_options": [0],
                "notes": [],
            }));
        }
        Err(status) => return Err(status),
    };
    let a_sum_pubkey = a_sum.public_key(&secp);
    let input_hash = calculate_input_hash(&outpoints_data, &a_sum_pubkey)?;

    if scan_group_recipient_limit_exceeded(groups) {
        return Ok(json!({
            "semantic_contract_version": SEMANTIC_CONTRACT_VERSION,
            "case_format_version": CASE_FORMAT_VERSION,
            "kind": "send",
            "source": request.source,
            "semantic_status": "recipient_limit_exceeded",
            "input_pubkeys": input_pubkeys,
            "input_hash": hex_encode(input_hash),
            "input_private_key_sum": hex_encode(a_sum.secret_bytes()),
            "sender_shared_secrets": shared_secret_entries,
            "acceptable_output_sets": [[]],
            "output_count_options": [0],
            "notes": ["per_group_recipient_limit_exceeded"],
        }));
    }

    let partial_secret = calculate_partial_secret(&eligible_keys, &outpoints_data)
        .map_err(|e| format!("failed to calculate partial secret: {}", e))?;
    let mut sender_shared_secrets = unique_scan_pubkeys(groups)
        .into_iter()
        .map(|scan_pubkey| {
            let scan_key = secp256k1::PublicKey::from_slice(
                &hex_decode(&scan_pubkey).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            let shared_secret = calculate_send_shared_secret(&scan_key, &partial_secret);
            Ok(SharedSecretEntry {
                scan_pubkey,
                shared_secret: Some(hex_encode(shared_secret.serialize())),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    sender_shared_secrets.sort_by(|left, right| left.scan_pubkey.cmp(&right.scan_pubkey));

    let recipients = build_recipient_list(groups, request.silent_payment_version, request.network.as_str())?;
    let outputs = generate_recipient_pubkeys(recipients, partial_secret)
        .map_err(|e| format!("failed to generate recipient pubkeys: {}", e))?;
    let mut output_set = BTreeSet::new();
    for output_keys in outputs.into_values() {
        for output_key in output_keys {
            output_set.insert(hex_encode(output_key.serialize()));
        }
    }
    let output_list = output_set.into_iter().collect::<Vec<_>>();

    Ok(json!({
        "semantic_contract_version": SEMANTIC_CONTRACT_VERSION,
        "case_format_version": CASE_FORMAT_VERSION,
        "kind": "send",
        "source": request.source,
        "semantic_status": "ok",
        "input_pubkeys": input_pubkeys,
        "input_hash": hex_encode(input_hash),
        "input_private_key_sum": hex_encode(a_sum.secret_bytes()),
        "sender_shared_secrets": sender_shared_secrets,
        "acceptable_output_sets": [output_list],
        "output_count_options": [output_list.len()],
        "notes": [],
    }))
}

fn derive_receive_semantics(request: &AdapterRequest) -> Result<Value> {
    let secp = secp256k1::Secp256k1::new();
    let outpoints_data = build_outpoints(request)?;
    let mut input_pubkeys = Vec::new();
    let mut eligible_pubkeys = Vec::new();
    for input in &request.inputs {
        if let Some(pubkey) = extract_pubkey(input)? {
            input_pubkeys.push(hex_encode(pubkey.serialize()));
            eligible_pubkeys.push(pubkey);
        }
    }

    let receiver_keys = request
        .receiver_keys
        .as_ref()
        .ok_or_else(|| "missing receiver_keys".to_owned())?;
    let b_scan = secp256k1::SecretKey::from_slice(
        &hex_decode(&receiver_keys.scan_privkey).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let b_spend = secp256k1::SecretKey::from_slice(
        &hex_decode(&receiver_keys.spend_privkey).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let network = map_network(request.network.as_str())?;

    let base_receiver = Receiver::new(
        u32::from(request.silent_payment_version),
        b_scan.public_key(&secp),
        b_spend.public_key(&secp),
        Label::new(b_scan, 0),
        network,
    )
    .map_err(|e| format!("failed to construct receiver: {}", e))?;
    let mut receiver = base_receiver.clone();
    let mut receiving_addresses = vec![base_receiver.get_receiving_address().to_string()];
    for label_value in request.labels.clone().unwrap_or_default() {
        let label = Label::new(b_scan, label_value);
        receiver
            .add_label(label.clone())
            .map_err(|e| format!("failed to add label {}: {}", label_value, e))?;
        receiving_addresses.push(
            receiver
                .get_receiving_address_for_label(&label)
                .map_err(|e| format!("failed to get label address {}: {}", label_value, e))?
                .to_string(),
        );
    }

    if eligible_pubkeys.is_empty() {
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

    let input_pubkey_refs = eligible_pubkeys.iter().collect::<Vec<_>>();
    let a_sum = secp256k1::PublicKey::combine_keys(&input_pubkey_refs)
        .map_err(|_| "point_at_infinity".to_owned());
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

    let input_hash = calculate_input_hash(&outpoints_data, &a_sum)?;
    let tweak_data = calculate_tweak_data(&input_pubkey_refs, &outpoints_data)
        .map_err(|e| format!("failed to calculate tweak data: {}", e))?;
    let shared_secret = calculate_receive_shared_secret(&tweak_data, &b_scan);
    let outputs_to_scan_hex = request
        .outputs_to_scan
        .clone()
        .unwrap_or_default();
    let detailed_outputs_required = request
        .expectation_hints
        .as_ref()
        .and_then(|hints| hints.detailed_outputs_required)
        .unwrap_or(true);
    let (detailed_outputs_available, found_output_count, found_outputs, notes) = scan_outputs(
        &secp,
        &shared_secret,
        &b_scan,
        &b_spend.public_key(&secp),
        request.labels.as_deref().unwrap_or(&[]),
        &outputs_to_scan_hex,
        !detailed_outputs_required,
    )?;

    Ok(json!({
        "semantic_contract_version": SEMANTIC_CONTRACT_VERSION,
        "case_format_version": CASE_FORMAT_VERSION,
        "kind": "receive",
        "source": request.source,
        "semantic_status": "ok",
        "input_pubkeys": input_pubkeys,
        "input_hash": hex_encode(input_hash),
        "receiving_addresses": receiving_addresses,
        "input_pubkey_sum": hex_encode(a_sum.serialize()),
        "tweak": hex_encode(tweak_data.serialize()),
        "shared_secret": hex_encode(shared_secret.serialize()),
        "detailed_outputs_available": detailed_outputs_available,
        "found_output_count": found_output_count,
        "found_outputs": found_outputs,
        "notes": notes,
    }))
}

fn extract_pubkey(input: &InputRequest) -> Result<Option<secp256k1::PublicKey>> {
    let script_sig = decode_optional_hex(input.script_sig.as_ref())?;
    let prevout_script_pubkey = decode_required_hex(
        input.prevout_script_pubkey.as_ref(),
        "missing prevout_script_pubkey",
    )?;
    let txinwitness = decode_hex_list(&input.txinwitness_stack)?;
    get_pubkey_from_input(&script_sig, &txinwitness, &prevout_script_pubkey)
        .map_err(|e| format!("failed to parse input pubkey: {}", e))
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

fn decode_hex_list(values: &[String]) -> Result<Vec<Vec<u8>>> {
    values
        .iter()
        .map(|value| hex_decode(value).map_err(|e| e.to_string()))
        .collect()
}

fn normalize_outputs_to_scan(outputs_to_scan: &[String]) -> Result<HashSet<String>> {
    let mut remaining = HashSet::new();
    for output in outputs_to_scan {
        let bytes = hex_decode(output).map_err(|e| e.to_string())?;
        let pubkey =
            secp256k1::XOnlyPublicKey::from_slice(&bytes).map_err(|_| "malformed public key".to_owned())?;
        remaining.insert(hex_encode(pubkey.serialize()));
    }
    Ok(remaining)
}

fn build_outpoints(request: &AdapterRequest) -> Result<Vec<(String, u32)>> {
    Ok(request
        .inputs
        .iter()
        .map(|input| (input.outpoint_txid.clone(), input.outpoint_vout))
        .collect())
}

fn scan_outputs(
    secp: &secp256k1::Secp256k1<secp256k1::All>,
    shared_secret: &secp256k1::PublicKey,
    b_scan: &secp256k1::SecretKey,
    b_spend: &secp256k1::PublicKey,
    labels: &[u32],
    outputs_to_scan: &[String],
    count_only: bool,
) -> Result<(bool, usize, Vec<FoundOutput>, Vec<String>)> {
    let mut remaining = normalize_outputs_to_scan(outputs_to_scan)?;
    let label_entries = build_label_entries(secp, *b_scan, b_spend, labels)?;
    let mut found_count = 0usize;
    let mut found_outputs = Vec::new();
    for index in 0..K_MAX {
        let tweak = shared_secret_tweak(shared_secret, index as u32)?;
        let base_output = b_spend
            .add_exp_tweak(secp, &tweak.into())
            .map_err(|e| format!("failed to derive receive output: {}", e))?;
        let base_xonly = hex_encode(base_output.x_only_public_key().0.serialize());
        if remaining.remove(&base_xonly) {
            found_count += 1;
            if !count_only {
                found_outputs.push(FoundOutput {
                    pub_key: base_xonly,
                    priv_key_tweak: hex_encode(tweak.secret_bytes()),
                });
            }
            continue;
        }
        let mut matched = false;
        for label in &label_entries {
            let output = label
                .spend_pubkey
                .add_exp_tweak(secp, &tweak.into())
                .map_err(|e| format!("failed to derive labeled receive output: {}", e))?;
            let output_xonly = hex_encode(output.x_only_public_key().0.serialize());
            if remaining.remove(&output_xonly) {
                found_count += 1;
                if !count_only {
                    let full_tweak = tweak
                        .add_tweak(&label.tweak.into())
                        .map_err(|e| format!("failed to combine label tweak: {}", e))?;
                    found_outputs.push(FoundOutput {
                        pub_key: output_xonly,
                        priv_key_tweak: hex_encode(full_tweak.secret_bytes()),
                    });
                }
                matched = true;
                break;
            }
        }
        if !matched {
            break;
        }
    }
    if !count_only {
        found_outputs.sort_by(|left, right| {
            (left.pub_key.as_str(), left.priv_key_tweak.as_str())
                .cmp(&(right.pub_key.as_str(), right.priv_key_tweak.as_str()))
        });
    }
    let mut notes = Vec::new();
    if outputs_to_scan.len() > K_MAX && found_count == K_MAX {
        notes.push("scan_limit_reached".to_owned());
    }
    if count_only {
        notes.push("count_only_expectation".to_owned());
    }
    Ok((!count_only, found_count, found_outputs, notes))
}

struct LabelEntry {
    spend_pubkey: secp256k1::PublicKey,
    tweak: secp256k1::SecretKey,
}

fn build_label_entries(
    secp: &secp256k1::Secp256k1<secp256k1::All>,
    b_scan: secp256k1::SecretKey,
    b_spend: &secp256k1::PublicKey,
    labels: &[u32],
) -> Result<Vec<LabelEntry>> {
    let mut entries = Vec::new();
    for label in labels {
        let tweak_bytes = tagged_hash("BIP0352/Label", &[&b_scan.secret_bytes()[..], &label.to_be_bytes()[..]].concat());
        let tweak = secp256k1::SecretKey::from_slice(&tweak_bytes).map_err(|e| e.to_string())?;
        let spend_pubkey = b_spend
            .combine(&tweak.public_key(secp))
            .map_err(|e| format!("failed to combine label spend pubkey: {}", e))?;
        entries.push(LabelEntry { spend_pubkey, tweak });
    }
    Ok(entries)
}

fn shared_secret_tweak(shared_secret: &secp256k1::PublicKey, index: u32) -> Result<secp256k1::SecretKey> {
    let tweak_bytes = tagged_hash(
        "BIP0352/SharedSecret",
        &[&shared_secret.serialize()[..], &index.to_be_bytes()[..]].concat(),
    );
    secp256k1::SecretKey::from_slice(&tweak_bytes).map_err(|e| e.to_string())
}

fn unique_scan_pubkeys(groups: &[RecipientGroupRequest]) -> Vec<String> {
    let mut ordered = Vec::new();
    let mut seen = HashSet::new();
    for group in groups {
        if seen.insert(group.scan_pubkey.clone()) {
            ordered.push(group.scan_pubkey.clone());
        }
    }
    ordered
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

fn build_recipient_list(
    groups: &[RecipientGroupRequest],
    version: u8,
    network_name: &str,
) -> Result<Vec<SilentPaymentAddress>> {
    let network = map_network(network_name)?;
    let mut recipients = Vec::new();
    for group in groups {
        let scan_pubkey = secp256k1::PublicKey::from_slice(
            &hex_decode(&group.scan_pubkey).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let spend_pubkey = secp256k1::PublicKey::from_slice(
            &hex_decode(&group.spend_pubkey).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let address = SilentPaymentAddress::new(scan_pubkey, spend_pubkey, network, version)
            .map_err(|e| format!("failed to construct address: {}", e))?;
        for _ in 0..usize::from(group.count) {
            recipients.push(address);
        }
    }
    Ok(recipients)
}

fn map_network(value: &str) -> Result<Network> {
    match value {
        "mainnet" => Ok(Network::Mainnet),
        "testnet" => Ok(Network::Testnet),
        "regtest" => Ok(Network::Regtest),
        _ => Err(format!("unsupported network: {}", value)),
    }
}

fn sum_input_secret_keys(
    input_keys: &[(secp256k1::SecretKey, bool)],
    secp: &secp256k1::Secp256k1<secp256k1::All>,
) -> std::result::Result<secp256k1::SecretKey, String> {
    if input_keys.is_empty() {
        return Err("no_eligible_inputs".to_owned());
    }
    let mut normalized = Vec::with_capacity(input_keys.len());
    for (key, is_taproot) in input_keys {
        let (_, parity) = key.x_only_public_key(secp);
        if *is_taproot && parity == secp256k1::Parity::Odd {
            normalized.push(key.negate());
        } else {
            normalized.push(*key);
        }
    }
    let mut iter = normalized.into_iter();
    let mut acc = iter.next().ok_or_else(|| "no_eligible_inputs".to_owned())?;
    for key in iter {
        acc = acc
            .add_tweak(&key.into())
            .map_err(|_| "zero_scalar".to_owned())?;
    }
    Ok(acc)
}

fn calculate_input_hash(
    outpoints_data: &[(String, u32)],
    a_sum: &secp256k1::PublicKey,
) -> Result<[u8; 32]> {
    if outpoints_data.is_empty() {
        return Err("no outpoints provided".to_owned());
    }

    let mut serialized = outpoints_data
        .iter()
        .map(|(txid, vout)| {
            let mut txid_bytes = hex_decode(txid).map_err(|e| e.to_string())?;
            if txid_bytes.len() != 32 {
                return Err(format!("invalid txid length: {}", txid));
            }
            txid_bytes.reverse();
            let mut outpoint = [0u8; 36];
            outpoint[..32].copy_from_slice(&txid_bytes);
            outpoint[32..].copy_from_slice(&vout.to_le_bytes());
            Ok(outpoint)
        })
        .collect::<Result<Vec<_>>>()?;
    serialized.sort_unstable();
    let mut message = Vec::with_capacity(69);
    message.extend_from_slice(&serialized[0]);
    message.extend_from_slice(&a_sum.serialize());
    Ok(tagged_hash("BIP0352/Inputs", &message))
}

fn tagged_hash(tag: &str, message: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    engine.input(message);
    sha256::Hash::from_engine(engine).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn receive_rejects_malformed_output_pubkeys() {
        let error = run_request_json(include_str!(
            "../../../tests/fixtures/receive_rejects_malformed_output_pubkeys.request.json"
        ))
        .expect_err("request should fail");
        assert_eq!(error, "malformed public key");
    }

    #[test]
    fn receive_rejects_malformed_output_before_point_at_infinity() {
        let error = run_request_json(include_str!(
            "../../../tests/fixtures/receive_rejects_malformed_output_before_point_at_infinity.request.json"
        ))
        .expect_err("request should fail");
        assert_eq!(error, "malformed public key");
    }
}
