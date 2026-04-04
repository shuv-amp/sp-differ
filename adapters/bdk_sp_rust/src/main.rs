use bdk_sp::bitcoin::hashes::{sha256, Hash, HashEngine};
use bdk_sp::bitcoin::secp256k1::{Parity, PublicKey, Scalar, SecretKey};
use bdk_sp::bitcoin::{
    Amount, Network as BitcoinNetwork, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Txid, Witness,
};
use bdk_sp::compute_shared_secret;
use bdk_sp::encoding::SilentPaymentCode;
use bdk_sp::receive::extract_pubkey;
use bdk_sp::send::{create_silentpayment_partial_secret, create_silentpayment_scriptpubkeys};
use bdk_sp::SpInputs;
use hex::{decode as hex_decode, encode as hex_encode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::{self, Read};
use std::str::FromStr;

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
    script_pubkey: ScriptBuf,
    is_taproot: bool,
    privkey: SecretKey,
}

struct EligibleReceiveInput {
    public_key: PublicKey,
}

struct LabelEntry {
    spend_pubkey: PublicKey,
    tweak: SecretKey,
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

fn run_request_json(input: &str) -> std::result::Result<String, String> {
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
    let secp = bdk_sp::bitcoin::key::Secp256k1::new();
    let groups = request
        .recipient_groups
        .as_ref()
        .ok_or_else(|| "missing recipient_groups".to_owned())?;
    let empty_shared_secrets = unique_scan_pubkeys(groups)
        .into_iter()
        .map(|scan_pubkey| SharedSecretEntry {
            scan_pubkey,
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
    let input_hash = calculate_input_hash(&request.inputs, &a_sum_pubkey)?;

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
            "sender_shared_secrets": empty_shared_secrets,
            "acceptable_output_sets": [[]],
            "output_count_options": [0],
            "notes": ["per_group_recipient_limit_exceeded"],
        }));
    }

    let recipients = build_recipient_list(groups, request.network.as_str())?;
    let mut smallest = request
        .inputs
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
    smallest.sort_unstable();
    let partial_secret = create_silentpayment_partial_secret(
        &smallest
            .first()
            .ok_or_else(|| "no outpoints provided".to_owned())
            .copied()?,
        &eligible
            .iter()
            .map(|entry| {
                let key = if entry.is_taproot {
                    let (_, parity) = entry.privkey.x_only_public_key(&secp);
                    if parity == Parity::Odd {
                        entry.privkey.negate()
                    } else {
                        entry.privkey
                    }
                } else {
                    entry.privkey
                };
                (entry.script_pubkey.clone(), key)
            })
            .collect::<Vec<_>>(),
    )
    .map_err(|e| e.to_string())?;

    let outputs = create_silentpayment_scriptpubkeys(partial_secret, &recipients);
    let mut output_set = BTreeSet::new();
    for values in outputs.values() {
        for output in values {
            output_set.insert(hex_encode(output.serialize()));
        }
    }
    let output_list = output_set.into_iter().collect::<Vec<_>>();

    let sender_shared_secrets = build_sender_shared_secrets(groups, &partial_secret)?;

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
        "acceptable_output_sets": [output_list.clone()],
        "output_count_options": [output_list.len()],
        "notes": [],
    }))
}

fn derive_receive_semantics(request: &AdapterRequest) -> Result<Value> {
    let secp = bdk_sp::bitcoin::key::Secp256k1::new();
    let eligible = collect_receive_inputs(request)?;
    let input_pubkeys = eligible
        .iter()
        .map(|entry| hex_encode(entry.public_key.serialize()))
        .collect::<Vec<_>>();

    let receiver_keys = request
        .receiver_keys
        .as_ref()
        .ok_or_else(|| "missing receiver_keys".to_owned())?;
    let scan_privkey_bytes = hex_decode(&receiver_keys.scan_privkey).map_err(|e| e.to_string())?;
    let spend_privkey_bytes = hex_decode(&receiver_keys.spend_privkey).map_err(|e| e.to_string())?;
    let b_scan = SecretKey::from_slice(&scan_privkey_bytes).map_err(|e| e.to_string())?;
    let b_spend = SecretKey::from_slice(&spend_privkey_bytes).map_err(|e| e.to_string())?;
    let scan_pubkey = b_scan.public_key(&secp);
    let spend_pubkey = b_spend.public_key(&secp);

    let labels = request.labels.clone().unwrap_or_default();
    let network = map_network(request.network.as_str())?;
    let base_code = SilentPaymentCode::new_v0(scan_pubkey, spend_pubkey, network);
    let mut receiving_addresses = vec![base_code.to_string()];
    for label in &labels {
        let tweak = SilentPaymentCode::get_label(b_scan, *label);
        let labeled = base_code
            .add_label(tweak)
            .map_err(|e| format!("failed to derive labeled address: {}", e))?;
        receiving_addresses.push(labeled.to_string());
    }

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

    let eligible_pubkeys = eligible.iter().map(|entry| entry.public_key).collect::<Vec<_>>();
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

    let input_hash = calculate_input_hash(&request.inputs, &a_sum)?;
    let tweak = derive_tweak_point(&a_sum, &input_hash, &secp)?;
    let shared_secret = compute_shared_secret(&b_scan, &tweak);

    let detailed_outputs_required = request
        .expectation_hints
        .as_ref()
        .and_then(|hints| hints.detailed_outputs_required)
        .unwrap_or(true);

    let (found_output_count, found_outputs, notes) = scan_outputs(
        &secp,
        &shared_secret,
        &b_scan,
        &spend_pubkey,
        &labels,
        request.outputs_to_scan.as_deref().unwrap_or(&[]),
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
        "tweak": hex_encode(tweak.serialize()),
        "shared_secret": hex_encode(shared_secret.serialize()),
        "detailed_outputs_available": detailed_outputs_required,
        "found_output_count": found_output_count,
        "found_outputs": found_outputs,
        "notes": notes,
    }))
}

fn collect_send_inputs(request: &AdapterRequest) -> Result<Vec<EligibleSendInput>> {
    let mut eligible = Vec::new();
    for input in &request.inputs {
        let (txin, prevout) = build_txin_and_prevout(input)?;
        let Some((kind, public_key)) = extract_pubkey(txin, &prevout.script_pubkey) else {
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
            script_pubkey: prevout.script_pubkey,
            is_taproot: matches!(kind, SpInputs::Tr),
            privkey,
        });
    }
    Ok(eligible)
}

fn collect_receive_inputs(request: &AdapterRequest) -> Result<Vec<EligibleReceiveInput>> {
    let mut eligible = Vec::new();
    for input in &request.inputs {
        let (txin, prevout) = build_txin_and_prevout(input)?;
        let Some((_, public_key)) = extract_pubkey(txin, &prevout.script_pubkey) else {
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
        sequence: Sequence::default(),
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

fn build_sender_shared_secrets(
    groups: &[RecipientGroupRequest],
    partial_secret: &SecretKey,
) -> Result<Vec<SharedSecretEntry>> {
    let mut entries = Vec::new();
    for scan_pubkey in unique_scan_pubkeys(groups) {
        let scan_key = PublicKey::from_slice(&hex_decode(&scan_pubkey).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        let shared_secret = compute_shared_secret(partial_secret, &scan_key);
        entries.push(SharedSecretEntry {
            scan_pubkey,
            shared_secret: Some(hex_encode(shared_secret.serialize())),
        });
    }
    entries.sort_by(|left, right| left.scan_pubkey.cmp(&right.scan_pubkey));
    Ok(entries)
}

fn calculate_input_hash(inputs: &[InputRequest], sum_input_pubkeys: &PublicKey) -> Result<[u8; 32]> {
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

fn derive_tweak_point(
    a_sum: &PublicKey,
    input_hash: &[u8; 32],
    secp: &bdk_sp::bitcoin::key::Secp256k1<bdk_sp::bitcoin::secp256k1::All>,
) -> Result<PublicKey> {
    let tweak = SecretKey::from_slice(input_hash).map_err(|e| e.to_string())?;
    a_sum
        .mul_tweak(secp, &Scalar::from(tweak))
        .map_err(|e| format!("failed to derive tweak point: {}", e))
}

fn build_recipient_list(groups: &[RecipientGroupRequest], network_name: &str) -> Result<Vec<SilentPaymentCode>> {
    let network = map_network(network_name)?;
    let mut recipients = Vec::new();
    for group in groups {
        let scan_pubkey =
            PublicKey::from_slice(&hex_decode(&group.scan_pubkey).map_err(|e| e.to_string())?)
                .map_err(|e| format!("failed to decode scan pubkey: {}", e))?;
        let spend_pubkey =
            PublicKey::from_slice(&hex_decode(&group.spend_pubkey).map_err(|e| e.to_string())?)
                .map_err(|e| format!("failed to decode spend pubkey: {}", e))?;
        let code = SilentPaymentCode::new_v0(scan_pubkey, spend_pubkey, network);
        for _ in 0..usize::from(group.count) {
            recipients.push(code.clone());
        }
    }
    Ok(recipients)
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

fn map_network(value: &str) -> Result<BitcoinNetwork> {
    match value {
        "mainnet" => Ok(BitcoinNetwork::Bitcoin),
        "testnet" => Ok(BitcoinNetwork::Testnet),
        "regtest" => Ok(BitcoinNetwork::Regtest),
        _ => Err(format!("unsupported network: {}", value)),
    }
}

fn scan_outputs(
    secp: &bdk_sp::bitcoin::key::Secp256k1<bdk_sp::bitcoin::secp256k1::All>,
    shared_secret: &PublicKey,
    b_scan: &SecretKey,
    b_spend: &PublicKey,
    labels: &[u32],
    outputs_to_scan: &[String],
    count_only: bool,
) -> Result<(usize, Vec<FoundOutput>, Vec<String>)> {
    let mut remaining = outputs_to_scan.iter().cloned().collect::<HashSet<String>>();
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
        return Ok((found_count, Vec::new(), notes));
    }
    Ok((found_count, found_outputs, notes))
}

fn build_label_entries(
    secp: &bdk_sp::bitcoin::key::Secp256k1<bdk_sp::bitcoin::secp256k1::All>,
    b_scan: SecretKey,
    b_spend: &PublicKey,
    labels: &[u32],
) -> Result<Vec<LabelEntry>> {
    let mut entries = Vec::new();
    for label in labels {
        let tweak = SilentPaymentCode::get_label(b_scan, *label);
        let tweak_sk = SecretKey::from_slice(&tweak.to_be_bytes()).map_err(|e| e.to_string())?;
        let spend_pubkey = b_spend
            .combine(&tweak_sk.public_key(secp))
            .map_err(|e| format!("failed to combine label spend pubkey: {}", e))?;
        entries.push(LabelEntry {
            spend_pubkey,
            tweak: tweak_sk,
        });
    }
    Ok(entries)
}

fn shared_secret_tweak(shared_secret: &PublicKey, index: u32) -> Result<SecretKey> {
    let tweak_bytes = tagged_hash(
        "BIP0352/SharedSecret",
        &[&shared_secret.serialize()[..], &index.to_be_bytes()[..]].concat(),
    );
    SecretKey::from_slice(&tweak_bytes).map_err(|e| e.to_string())
}

fn sum_input_secret_keys(
    input_keys: &[(SecretKey, bool)],
    secp: &bdk_sp::bitcoin::key::Secp256k1<bdk_sp::bitcoin::secp256k1::All>,
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

fn tagged_hash(tag: &str, message: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_byte_array());
    engine.input(tag_hash.as_byte_array());
    engine.input(message);
    sha256::Hash::from_engine(engine).to_byte_array()
}
