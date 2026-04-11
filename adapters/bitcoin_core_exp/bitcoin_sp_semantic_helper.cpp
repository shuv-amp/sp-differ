// SPDX-License-Identifier: MIT

#include <addresstype.h>
#include <common/bip352.h>
#include <key.h>
#include <pubkey.h>
#include <script/script.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <boost/multiprecision/cpp_int.hpp>

#include <algorithm>
#include <cstdint>
#include <exception>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {
using boost::multiprecision::cpp_int;

constexpr uint32_t SEMANTIC_ADAPTER_REQUEST_VERSION = 1;
constexpr uint32_t CASE_FORMAT_VERSION = 2;
constexpr size_t K_MAX = 2323;

struct SendInput {
    COutPoint outpoint;
    CKey key;
    bool is_taproot;
};

std::string ReadStdin()
{
    return {std::istreambuf_iterator<char>(std::cin), std::istreambuf_iterator<char>()};
}

void Require(bool condition, std::string_view message)
{
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

UniValue ParseJson(const std::string& input)
{
    UniValue root;
    Require(root.read(input), "invalid JSON");
    Require(root.isObject(), "request must be a JSON object");
    return root;
}

std::vector<unsigned char> ParseHexString(std::string_view value, std::string_view field_name)
{
    if (value.empty()) {
        return {};
    }
    Require(IsHex(value), std::string(field_name) + " must be hex");
    return ParseHex(value);
}

std::string HexXOnly(const XOnlyPubKey& pubkey)
{
    return HexStr(std::span<const unsigned char>{pubkey.begin(), pubkey.end()});
}

std::string HexCompressed(const CPubKey& pubkey)
{
    return HexStr(std::span<const unsigned char>{pubkey.begin(), pubkey.end()});
}

std::string HexUint256Bytes(const uint256& value)
{
    return HexStr(std::span<const unsigned char>{value.begin(), value.end()});
}

const cpp_int& SecpOrder()
{
    static const cpp_int order = [] {
        cpp_int value = 0;
        const auto bytes = ParseHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
        for (unsigned char byte : bytes) {
            value <<= 8;
            value += byte;
        }
        return value;
    }();
    return order;
}

cpp_int ScalarFromKey(const CKey& key)
{
    cpp_int value = 0;
    for (auto it = key.begin(); it != key.end(); ++it) {
        value <<= 8;
        value += *it;
    }
    return value;
}

bool SumInputsIsZero(const std::vector<SendInput>& inputs)
{
    const cpp_int& order = SecpOrder();
    cpp_int sum = 0;
    for (const auto& input : inputs) {
        cpp_int scalar = ScalarFromKey(input.key);
        if (input.is_taproot) {
            const CPubKey pubkey = input.key.GetPubKey();
            Require(pubkey.IsValid() && pubkey.IsCompressed(), "failed to derive taproot pubkey");
            if (pubkey[0] == 0x03) {
                scalar = (order - scalar) % order;
            }
        }
        sum += scalar;
        sum %= order;
    }
    return sum == 0;
}

bool IsEligibleSendType(std::string_view input_type)
{
    return input_type == "p2wpkh" || input_type == "p2tr" || input_type == "p2sh-p2wpkh" ||
           input_type == "p2pkh";
}

bool HasTaprootScriptPathSpend(const CTxIn& txin)
{
    if (txin.scriptWitness.stack.size() <= 1) {
        return false;
    }
    const auto& stack = txin.scriptWitness.stack;
    const bool has_annex = !stack.empty() && !stack.back().empty() && stack.back().front() == ANNEX_TAG;
    const size_t post_annex_size = stack.size() - (has_annex ? 1 : 0);
    return post_annex_size > 1;
}

CKey ParseSecretKeyField(const UniValue& value, std::string_view field_name)
{
    Require(value.isStr(), std::string(field_name) + " must be a string");
    const auto bytes = ParseHexString(value.get_str(), field_name);
    Require(bytes.size() == 32, std::string(field_name) + " must be 32 bytes");
    CKey key;
    key.Set(bytes.begin(), bytes.end(), true);
    Require(key.IsValid(), std::string(field_name) + " is not a valid secp256k1 secret key");
    return key;
}

CPubKey ParseCompressedPubKeyField(const UniValue& value, std::string_view field_name)
{
    Require(value.isStr(), std::string(field_name) + " must be a string");
    const auto bytes = ParseHexString(value.get_str(), field_name);
    Require(bytes.size() == CPubKey::COMPRESSED_SIZE, std::string(field_name) + " must be 33 bytes");
    CPubKey pubkey{bytes};
    Require(pubkey.IsValid() && pubkey.IsCompressed(), std::string(field_name) + " is not a valid compressed pubkey");
    return pubkey;
}

XOnlyPubKey ParseXOnlyPubKeyField(const UniValue& value, std::string_view field_name)
{
    Require(value.isStr(), std::string(field_name) + " must be a string");
    const auto bytes = ParseHexString(value.get_str(), field_name);
    Require(bytes.size() == XOnlyPubKey::size(), std::string(field_name) + " must be 32 bytes");
    XOnlyPubKey pubkey{std::span<const unsigned char>{bytes.data(), bytes.size()}};
    Require(pubkey.IsFullyValid(), std::string(field_name) + " is not a valid xonly pubkey");
    return pubkey;
}

CTxIn ParseInputTxIn(const UniValue& entry)
{
    Require(entry.isObject(), "input entry must be an object");
    const auto txid = Txid::FromHex(entry["outpoint_txid"].get_str());
    Require(txid.has_value(), "invalid outpoint_txid");
    const auto vout = entry["outpoint_vout"].getInt<uint32_t>();

    CScript script_sig;
    if (entry["script_sig"].isStr()) {
        const auto script_sig_bytes = ParseHexString(entry["script_sig"].get_str(), "script_sig");
        script_sig = CScript(script_sig_bytes.begin(), script_sig_bytes.end());
    }

    CTxIn txin{COutPoint{*txid, vout}, script_sig};
    CScriptWitness witness;
    const UniValue& stack = entry["txinwitness_stack"];
    Require(stack.isArray(), "txinwitness_stack must be an array");
    for (const auto& item : stack.getValues()) {
        const auto bytes = ParseHexString(item.get_str(), "txinwitness_stack item");
        witness.stack.push_back(bytes);
    }
    txin.scriptWitness = witness;
    return txin;
}

std::map<size_t, V0SilentPaymentDestination> ParseRecipients(const UniValue& groups)
{
    Require(groups.isArray(), "recipient_groups must be an array");
    std::map<size_t, V0SilentPaymentDestination> recipients;
    size_t index = 0;
    for (const auto& group : groups.getValues()) {
        Require(group.isObject(), "recipient_group must be an object");
        const CPubKey scan_pubkey = ParseCompressedPubKeyField(group["scan_pubkey"], "scan_pubkey");
        const CPubKey spend_pubkey = ParseCompressedPubKeyField(group["spend_pubkey"], "spend_pubkey");
        const auto count = group["count"].getInt<int>();
        Require(count > 0, "recipient count must be positive");
        for (int i = 0; i < count; ++i) {
            recipients.emplace(index++, V0SilentPaymentDestination{scan_pubkey, spend_pubkey});
        }
    }
    return recipients;
}

bool RecipientLimitExceeded(const UniValue& groups)
{
    std::map<std::string, size_t> per_scan_counts;
    for (const auto& group : groups.getValues()) {
        const std::string scan_pubkey = group["scan_pubkey"].get_str();
        const auto count = group["count"].getInt<size_t>();
        per_scan_counts[scan_pubkey] += count;
        if (per_scan_counts[scan_pubkey] > K_MAX) {
            return true;
        }
    }
    return false;
}

UniValue RunSend(const UniValue& request)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("kind", "send");

    const UniValue& inputs = request["inputs"];
    const UniValue& recipient_groups = request["recipient_groups"];
    Require(inputs.isArray(), "inputs must be an array");
    Require(recipient_groups.isArray(), "recipient_groups must be an array");

    std::vector<COutPoint> outpoints;
    std::vector<SendInput> eligible_inputs;
    std::vector<CKey> plain_keys;
    std::vector<KeyPair> taproot_keys;
    outpoints.reserve(inputs.size());

    for (const auto& entry : inputs.getValues()) {
        Require(entry.isObject(), "input entry must be an object");
        const auto txid = Txid::FromHex(entry["outpoint_txid"].get_str());
        Require(txid.has_value(), "invalid outpoint_txid");
        const auto vout = entry["outpoint_vout"].getInt<uint32_t>();
        outpoints.emplace_back(*txid, vout);

        const std::string input_type = entry["input_type"].get_str();
        if (!IsEligibleSendType(input_type)) {
            continue;
        }
        if (!entry["privkey"].isStr()) {
            continue;
        }
        Require(entry["prevout_script_pubkey"].isStr(), "prevout_script_pubkey must be a string");
        const auto spk_bytes = ParseHexString(entry["prevout_script_pubkey"].get_str(), "prevout_script_pubkey");
        const CScript script_pubkey{spk_bytes.begin(), spk_bytes.end()};
        const CTxIn txin = ParseInputTxIn(entry);
        const auto parsed_pubkey = bip352::GetPubKeyFromInput(txin, script_pubkey);
        if (!parsed_pubkey.has_value()) {
            continue;
        }
        const CKey key = ParseSecretKeyField(entry["privkey"], "privkey");
        const bool is_taproot = std::holds_alternative<XOnlyPubKey>(*parsed_pubkey);
        if (is_taproot && HasTaprootScriptPathSpend(txin)) {
            continue;
        }
        if (const auto* plain_pubkey = std::get_if<CPubKey>(&*parsed_pubkey)) {
            if (key.GetPubKey() != *plain_pubkey) {
                continue;
            }
        }
        eligible_inputs.push_back(SendInput{COutPoint{*txid, vout}, key, is_taproot});
        if (is_taproot) {
            taproot_keys.push_back(key.ComputeKeyPair(nullptr));
        } else {
            plain_keys.push_back(key);
        }
    }

    if (eligible_inputs.empty()) {
        result.pushKV("semantic_status", "no_eligible_inputs");
        result.pushKV("outputs", UniValue(UniValue::VARR));
        return result;
    }

    if (SumInputsIsZero(eligible_inputs)) {
        result.pushKV("semantic_status", "zero_scalar");
        result.pushKV("outputs", UniValue(UniValue::VARR));
        return result;
    }

    if (RecipientLimitExceeded(recipient_groups)) {
        result.pushKV("semantic_status", "recipient_limit_exceeded");
        result.pushKV("outputs", UniValue(UniValue::VARR));
        return result;
    }

    const auto recipients = ParseRecipients(recipient_groups);
    Require(!outpoints.empty(), "missing inputs");
    const auto smallest_outpoint = std::min_element(outpoints.begin(), outpoints.end(), bip352::BIP352Comparator());
    const auto outputs = bip352::GenerateSilentPaymentTaprootDestinations(
        recipients,
        plain_keys,
        taproot_keys,
        *smallest_outpoint
    );

    if (!outputs.has_value()) {
        result.pushKV("semantic_status", "internal");
        result.pushKV("outputs", UniValue(UniValue::VARR));
        return result;
    }

    UniValue serialized_outputs(UniValue::VARR);
    for (const auto& [_, output] : *outputs) {
        serialized_outputs.push_back(HexXOnly(output));
    }
    result.pushKV("semantic_status", "ok");
    result.pushKV("outputs", std::move(serialized_outputs));
    return result;
}

std::map<COutPoint, Coin> BuildCoins(const UniValue& inputs)
{
    std::map<COutPoint, Coin> coins;
    for (const auto& entry : inputs.getValues()) {
        const auto txid = Txid::FromHex(entry["outpoint_txid"].get_str());
        Require(txid.has_value(), "invalid outpoint_txid");
        const auto vout = entry["outpoint_vout"].getInt<uint32_t>();
        Require(entry["prevout_script_pubkey"].isStr(), "prevout_script_pubkey must be a string");
        const auto spk_bytes = ParseHexString(entry["prevout_script_pubkey"].get_str(), "prevout_script_pubkey");
        CScript script_pubkey{spk_bytes.begin(), spk_bytes.end()};
        coins.emplace(COutPoint{*txid, vout}, Coin{CTxOut{{}, script_pubkey}, 0, false});
    }
    return coins;
}

std::vector<CTxIn> BuildVin(const UniValue& inputs)
{
    std::vector<CTxIn> vin;
    vin.reserve(inputs.size());
    for (const auto& entry : inputs.getValues()) {
        vin.push_back(ParseInputTxIn(entry));
    }
    return vin;
}

size_t CountEligibleReceiveInputs(const std::vector<CTxIn>& vin, const std::map<COutPoint, Coin>& coins)
{
    size_t eligible = 0;
    for (const auto& txin : vin) {
        const auto coin_it = coins.find(txin.prevout);
        Require(coin_it != coins.end(), "missing coin for input");
        if (bip352::GetPubKeyFromInput(txin, coin_it->second.out.scriptPubKey).has_value()) {
            ++eligible;
        }
    }
    return eligible;
}

std::map<CPubKey, uint256> BuildLabels(const CKey& scan_key, const UniValue& labels)
{
    std::map<CPubKey, uint256> result;
    const auto& [change_pubkey, change_tweak] = bip352::CreateLabelTweak(scan_key, 0);
    result.emplace(change_pubkey, change_tweak);
    for (const auto& item : labels.getValues()) {
        const auto label = item.getInt<int>();
        const auto& [label_pubkey, label_tweak] = bip352::CreateLabelTweak(scan_key, label);
        result[label_pubkey] = label_tweak;
    }
    return result;
}

UniValue RunReceive(const UniValue& request)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("kind", "receive");
    result.pushKV("detailed_outputs_available", true);

    const UniValue& inputs = request["inputs"];
    const UniValue& outputs_to_scan = request["outputs_to_scan"];
    const UniValue& receiver_keys = request["receiver_keys"];
    const UniValue& labels = request["labels"];
    Require(inputs.isArray(), "inputs must be an array");
    Require(outputs_to_scan.isArray(), "outputs_to_scan must be an array");
    Require(receiver_keys.isObject(), "receiver_keys must be an object");
    Require(labels.isArray(), "labels must be an array");

    const std::vector<CTxIn> vin = BuildVin(inputs);
    const std::map<COutPoint, Coin> coins = BuildCoins(inputs);
    if (CountEligibleReceiveInputs(vin, coins) == 0) {
        result.pushKV("semantic_status", "no_eligible_inputs");
        result.pushKV("found_output_count", 0);
        result.pushKV("found_outputs", UniValue(UniValue::VARR));
        return result;
    }

    const auto prevouts_summary = bip352::GetSilentPaymentsPrevoutsSummary(vin, coins);
    if (!prevouts_summary.has_value()) {
        result.pushKV("semantic_status", "point_at_infinity");
        result.pushKV("found_output_count", 0);
        result.pushKV("found_outputs", UniValue(UniValue::VARR));
        return result;
    }

    const CKey scan_key = ParseSecretKeyField(receiver_keys["scan_privkey"], "receiver_keys.scan_privkey");
    const CKey spend_key = ParseSecretKeyField(receiver_keys["spend_privkey"], "receiver_keys.spend_privkey");
    std::vector<XOnlyPubKey> output_pub_keys;
    output_pub_keys.reserve(outputs_to_scan.size());
    for (const auto& item : outputs_to_scan.getValues()) {
        output_pub_keys.push_back(ParseXOnlyPubKeyField(item, "outputs_to_scan"));
    }
    const auto found_outputs = bip352::ScanForSilentPaymentOutputs(
        scan_key,
        *prevouts_summary,
        spend_key.GetPubKey(),
        output_pub_keys,
        BuildLabels(scan_key, labels)
    );

    UniValue serialized_outputs(UniValue::VARR);
    size_t found_count = 0;
    if (found_outputs.has_value()) {
        found_count = found_outputs->size();
        for (const auto& item : *found_outputs) {
            UniValue output(UniValue::VOBJ);
            output.pushKV("pub_key", HexXOnly(item.output));
            output.pushKV("priv_key_tweak", HexUint256Bytes(item.tweak));
            serialized_outputs.push_back(std::move(output));
        }
    }

    result.pushKV("semantic_status", "ok");
    result.pushKV("found_output_count", static_cast<uint64_t>(found_count));
    result.pushKV("found_outputs", std::move(serialized_outputs));
    return result;
}

UniValue HandleRequest(const UniValue& request)
{
    Require(request["semantic_adapter_request_version"].getInt<int>() == static_cast<int>(SEMANTIC_ADAPTER_REQUEST_VERSION),
            "unsupported semantic adapter request version");
    Require(request["case_format_version"].getInt<int>() == static_cast<int>(CASE_FORMAT_VERSION),
            "case_format_version must be 2");
    const std::string kind = request["kind"].get_str();
    if (kind == "send") {
        return RunSend(request);
    }
    if (kind == "receive") {
        return RunReceive(request);
    }
    throw std::runtime_error("unknown kind");
}
} // namespace

int main()
{
    try {
        ECC_Context ecc_context;
        const UniValue request = ParseJson(ReadStdin());
        const UniValue response = HandleRequest(request);
        std::cout << response.write() << "\n";
        return 0;
    } catch (const std::exception& exc) {
        std::cerr << "error: " << exc.what() << "\n";
        return 2;
    }
}
