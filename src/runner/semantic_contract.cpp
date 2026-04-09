// SPDX-License-Identifier: MIT
#include "semantic_contract.hpp"

#include "semantic_bridge.hpp"

#include <algorithm>
#include <set>
#include <sstream>

namespace sp_differ {
namespace {

std::vector<uint8_t> ToBytes(const std::string& text) {
  return std::vector<uint8_t>(text.begin(), text.end());
}

std::string BytesToString(const std::vector<uint8_t>& bytes) {
  return std::string(bytes.begin(), bytes.end());
}

bool IsKnownKind(const std::string& value) {
  return value == "send" || value == "receive";
}

bool IsKnownSemanticStatus(const std::string& value) {
  return value == "ok" || value == "no_eligible_inputs" || value == "zero_scalar" ||
         value == "point_at_infinity" || value == "recipient_limit_exceeded" ||
         value == "invalid_input" || value == "invalid_pubkey" ||
         value == "tweak_out_of_range" || value == "internal";
}

int HexValue(char ch) {
  if (ch >= '0' && ch <= '9') {
    return ch - '0';
  }
  if (ch >= 'a' && ch <= 'f') {
    return 10 + (ch - 'a');
  }
  if (ch >= 'A' && ch <= 'F') {
    return 10 + (ch - 'A');
  }
  return -1;
}

bool IsHexString(const std::string& value, size_t expected_len = 0) {
  if (expected_len != 0 && value.size() != expected_len) {
    return false;
  }
  if ((value.size() & 1U) != 0) {
    return false;
  }
  for (char ch : value) {
    if (HexValue(ch) < 0) {
      return false;
    }
  }
  return true;
}

JsonArray SortedUniqueStrings(const JsonArray& raw, const char* what) {
  std::set<std::string> values;
  for (const JsonValue& item : raw) {
    values.insert(RequireString(item, what));
  }
  JsonArray canonical;
  for (const std::string& value : values) {
    canonical.emplace_back(value);
  }
  return canonical;
}

JsonArray NormalizeOutputSets(const JsonArray& raw) {
  std::set<std::vector<std::string>> canonical_sets;
  for (const JsonValue& value : raw) {
    const JsonArray& output_set = RequireArray(value, "invalid acceptable_output_set");
    std::set<std::string> deduped;
    for (const JsonValue& item : output_set) {
      const std::string& output = RequireString(item, "invalid output xonly pubkey");
      if (!IsHexString(output, 64)) {
        throw SemanticBridgeError("invalid output xonly pubkey");
      }
      deduped.insert(output);
    }
    canonical_sets.insert(std::vector<std::string>(deduped.begin(), deduped.end()));
  }

  JsonArray normalized;
  for (const auto& entry : canonical_sets) {
    JsonArray output_set;
    for (const std::string& output : entry) {
      output_set.emplace_back(output);
    }
    normalized.emplace_back(std::move(output_set));
  }
  return normalized;
}

JsonArray NormalizeSharedSecrets(const JsonArray& raw) {
  std::vector<JsonObject> entries;
  for (const JsonValue& value : raw) {
    const JsonObject& object = RequireObject(value, "invalid sender_shared_secrets item");
    const std::string& scan_pubkey = RequireString(RequireField(object, "scan_pubkey"),
                                                   "scan_pubkey");
    if (!IsHexString(scan_pubkey, 66)) {
      throw SemanticBridgeError("invalid scan_pubkey");
    }
    JsonValue shared_secret = nullptr;
    const auto shared_secret_it = object.find("shared_secret");
    if (shared_secret_it != object.end() && !shared_secret_it->second.is_null()) {
      const std::string& encoded = RequireString(shared_secret_it->second, "shared_secret");
      if (!IsHexString(encoded, 66)) {
        throw SemanticBridgeError("invalid shared_secret");
      }
      shared_secret = encoded;
    }
    JsonObject entry;
    entry["scan_pubkey"] = scan_pubkey;
    entry["shared_secret"] = shared_secret;
    entries.push_back(std::move(entry));
  }

  std::sort(entries.begin(), entries.end(),
            [](const JsonObject& left, const JsonObject& right) {
              return left.at("scan_pubkey").as_string() < right.at("scan_pubkey").as_string();
            });

  JsonArray normalized;
  for (JsonObject& entry : entries) {
    normalized.emplace_back(std::move(entry));
  }
  return normalized;
}

JsonArray NormalizeFoundOutputs(const JsonArray& raw, bool detailed_outputs_available,
                                int64_t found_output_count) {
  if (detailed_outputs_available &&
      static_cast<int64_t>(raw.size()) != found_output_count) {
    throw SemanticBridgeError("detailed found_outputs length mismatch");
  }

  std::set<std::pair<std::string, std::string>> seen;
  for (const JsonValue& value : raw) {
    const JsonObject& object = RequireObject(value, "invalid found_outputs item");
    const std::string& pub_key =
        RequireString(RequireField(object, "pub_key"), "found_outputs.pub_key");
    const std::string& tweak =
        RequireString(RequireField(object, "priv_key_tweak"), "found_outputs.priv_key_tweak");
    if (!IsHexString(pub_key, 64)) {
      throw SemanticBridgeError("invalid found_outputs.pub_key");
    }
    if (!IsHexString(tweak, 64)) {
      throw SemanticBridgeError("invalid found_outputs.priv_key_tweak");
    }
    seen.emplace(pub_key, tweak);
  }

  JsonArray normalized;
  for (const auto& item : seen) {
    JsonObject value;
    value["pub_key"] = item.first;
    value["priv_key_tweak"] = item.second;
    normalized.emplace_back(std::move(value));
  }
  return normalized;
}

}  // namespace

JsonValue ValidateSemanticResultValue(const JsonValue& raw_value) {
  const JsonObject& raw = RequireObject(raw_value, "semantic result");

  if (RequireInt(RequireField(raw, "semantic_contract_version"),
                 "semantic_contract_version") != kSemanticContractVersion) {
    throw SemanticBridgeError("unsupported semantic contract version");
  }
  if (RequireInt(RequireField(raw, "case_format_version"), "case_format_version") != 2) {
    throw SemanticBridgeError("case_format_version must be 2");
  }

  const std::string& kind = RequireString(RequireField(raw, "kind"), "kind");
  if (!IsKnownKind(kind)) {
    throw SemanticBridgeError("unknown kind");
  }
  const std::string& semantic_status =
      RequireString(RequireField(raw, "semantic_status"), "semantic_status");
  if (!IsKnownSemanticStatus(semantic_status)) {
    throw SemanticBridgeError("unknown semantic_status");
  }

  const JsonObject& source = RequireObject(RequireField(raw, "source"), "source");
  const auto source_kind_it = source.find("kind");
  if (source_kind_it == source.end() || !source_kind_it->second.is_string() ||
      !IsKnownKind(source_kind_it->second.as_string())) {
    throw SemanticBridgeError("invalid source.kind");
  }
  if (source.find("comment") == source.end() ||
      !RequireField(source, "comment").is_string()) {
    throw SemanticBridgeError("invalid source.comment");
  }
  if (source.find("case_index") == source.end() ||
      !RequireField(source, "case_index").is_int()) {
    throw SemanticBridgeError("invalid source.case_index");
  }
  if (source.find("entry_index") == source.end() ||
      !RequireField(source, "entry_index").is_int()) {
    throw SemanticBridgeError("invalid source.entry_index");
  }
  if (source.find("id") == source.end() || !RequireField(source, "id").is_string() ||
      RequireField(source, "id").as_string().empty()) {
    throw SemanticBridgeError("invalid source.id");
  }

  JsonArray input_pubkeys;
  for (const JsonValue& value : RequireArray(RequireField(raw, "input_pubkeys"),
                                             "input_pubkeys")) {
    const std::string& pubkey = RequireString(value, "input_pubkey");
    if (!IsHexString(pubkey, 66)) {
      throw SemanticBridgeError("invalid input_pubkey");
    }
    input_pubkeys.emplace_back(pubkey);
  }

  JsonValue input_hash = nullptr;
  const auto input_hash_it = raw.find("input_hash");
  if (input_hash_it != raw.end() && !input_hash_it->second.is_null()) {
    const std::string& value = RequireString(input_hash_it->second, "input_hash");
    if (!IsHexString(value, 64)) {
      throw SemanticBridgeError("invalid input_hash");
    }
    input_hash = value;
  }

  JsonArray notes = SortedUniqueStrings(RequireArray(RequireField(raw, "notes"), "notes"),
                                        "note");

  JsonObject canonical;
  canonical["semantic_contract_version"] = kSemanticContractVersion;
  canonical["case_format_version"] = static_cast<int64_t>(2);
  canonical["kind"] = kind;
  canonical["source"] = source;
  canonical["semantic_status"] = semantic_status;
  canonical["input_pubkeys"] = std::move(input_pubkeys);
  canonical["input_hash"] = std::move(input_hash);
  canonical["notes"] = std::move(notes);

  if (kind == "send") {
    JsonValue input_private_key_sum = nullptr;
    const auto private_sum_it = raw.find("input_private_key_sum");
    if (private_sum_it != raw.end() && !private_sum_it->second.is_null()) {
      const std::string& value =
          RequireString(private_sum_it->second, "input_private_key_sum");
      if (!IsHexString(value, 64)) {
        throw SemanticBridgeError("invalid input_private_key_sum");
      }
      input_private_key_sum = value;
    }

    const JsonArray normalized_shared_secrets = NormalizeSharedSecrets(
        RequireArray(RequireField(raw, "sender_shared_secrets"), "sender_shared_secrets"));
    const JsonArray normalized_output_sets = NormalizeOutputSets(
        RequireArray(RequireField(raw, "acceptable_output_sets"), "acceptable_output_sets"));

    const JsonArray& raw_output_count_options =
        RequireArray(RequireField(raw, "output_count_options"), "output_count_options");
    for (const JsonValue& value : raw_output_count_options) {
      const int64_t count = RequireInt(value, "output_count_option");
      if (count < 0) {
        throw SemanticBridgeError("invalid output_count_option");
      }
    }

    std::set<int64_t> count_options;
    for (const JsonValue& value : normalized_output_sets) {
      count_options.insert(static_cast<int64_t>(value.as_array().size()));
    }
    JsonArray normalized_count_options;
    for (int64_t count : count_options) {
      normalized_count_options.emplace_back(count);
    }

    canonical["input_private_key_sum"] = std::move(input_private_key_sum);
    canonical["sender_shared_secrets"] = normalized_shared_secrets;
    canonical["acceptable_output_sets"] = normalized_output_sets;
    canonical["output_count_options"] = std::move(normalized_count_options);
    return JsonValue(std::move(canonical));
  }

  JsonArray receiving_addresses;
  for (const JsonValue& value : RequireArray(RequireField(raw, "receiving_addresses"),
                                             "receiving_addresses")) {
    const std::string& address = RequireString(value, "receiving address");
    if (address.empty()) {
      throw SemanticBridgeError("invalid receiving address");
    }
    receiving_addresses.emplace_back(address);
  }

  JsonValue input_pubkey_sum = nullptr;
  const auto input_pubkey_sum_it = raw.find("input_pubkey_sum");
  if (input_pubkey_sum_it != raw.end() && !input_pubkey_sum_it->second.is_null()) {
    const std::string& value =
        RequireString(input_pubkey_sum_it->second, "input_pubkey_sum");
    if (!IsHexString(value, 66)) {
      throw SemanticBridgeError("invalid input_pubkey_sum");
    }
    input_pubkey_sum = value;
  }

  JsonValue tweak = nullptr;
  const auto tweak_it = raw.find("tweak");
  if (tweak_it != raw.end() && !tweak_it->second.is_null()) {
    const std::string& value = RequireString(tweak_it->second, "tweak");
    if (!IsHexString(value, 66)) {
      throw SemanticBridgeError("invalid tweak");
    }
    tweak = value;
  }

  JsonValue shared_secret = nullptr;
  const auto shared_secret_it = raw.find("shared_secret");
  if (shared_secret_it != raw.end() && !shared_secret_it->second.is_null()) {
    const std::string& value = RequireString(shared_secret_it->second, "shared_secret");
    if (!IsHexString(value, 66)) {
      throw SemanticBridgeError("invalid shared_secret");
    }
    shared_secret = value;
  }

  const bool detailed_outputs_available = RequireBool(
      RequireField(raw, "detailed_outputs_available"), "detailed_outputs_available");
  const int64_t found_output_count =
      RequireInt(RequireField(raw, "found_output_count"), "found_output_count");
  if (found_output_count < 0) {
    throw SemanticBridgeError("invalid found_output_count");
  }

  const JsonArray normalized_found_outputs = NormalizeFoundOutputs(
      RequireArray(RequireField(raw, "found_outputs"), "found_outputs"),
      detailed_outputs_available, found_output_count);

  canonical["receiving_addresses"] = std::move(receiving_addresses);
  canonical["input_pubkey_sum"] = std::move(input_pubkey_sum);
  canonical["tweak"] = std::move(tweak);
  canonical["shared_secret"] = std::move(shared_secret);
  canonical["detailed_outputs_available"] = detailed_outputs_available;
  canonical["found_output_count"] = found_output_count;
  canonical["found_outputs"] = normalized_found_outputs;
  return JsonValue(std::move(canonical));
}

std::vector<std::string> CompareSemanticResults(const JsonValue& expected_value,
                                                const JsonValue& actual_value) {
  const JsonObject& expected = expected_value.as_object();
  const JsonObject& actual = actual_value.as_object();
  std::vector<std::string> errors;

  const char* shared_keys[] = {"semantic_contract_version", "case_format_version", "kind",
                               "semantic_status", "source", "input_pubkeys",
                               "input_hash"};
  for (const char* key : shared_keys) {
    if (expected.at(key).value != actual.at(key).value) {
      errors.emplace_back(std::string("field mismatch: ") + key);
    }
  }

  if (expected.at("kind").as_string() == "send") {
    const char* send_keys[] = {"input_private_key_sum", "sender_shared_secrets"};
    for (const char* key : send_keys) {
      if (expected.at(key).value != actual.at(key).value) {
        errors.emplace_back(std::string("field mismatch: ") + key);
      }
    }

    std::set<std::vector<std::string>> expected_sets;
    for (const JsonValue& value : expected.at("acceptable_output_sets").as_array()) {
      std::vector<std::string> output_set;
      for (const JsonValue& item : value.as_array()) {
        output_set.push_back(item.as_string());
      }
      expected_sets.insert(std::move(output_set));
    }

    std::set<std::vector<std::string>> actual_sets;
    for (const JsonValue& value : actual.at("acceptable_output_sets").as_array()) {
      std::vector<std::string> output_set;
      for (const JsonValue& item : value.as_array()) {
        output_set.push_back(item.as_string());
      }
      actual_sets.insert(std::move(output_set));
    }

    if (actual_sets.empty()) {
      errors.emplace_back("actual acceptable_output_sets is empty");
    } else {
      for (const auto& output_set : actual_sets) {
        if (expected_sets.find(output_set) == expected_sets.end()) {
          errors.emplace_back("actual acceptable_output_sets not accepted by expected contract");
          break;
        }
      }
    }

    std::set<int64_t> expected_counts;
    for (const JsonValue& value : expected.at("output_count_options").as_array()) {
      expected_counts.insert(value.as_int());
    }
    for (const JsonValue& value : actual.at("output_count_options").as_array()) {
      if (expected_counts.find(value.as_int()) == expected_counts.end()) {
        errors.emplace_back("actual output_count_options not accepted by expected contract");
        break;
      }
    }
    return errors;
  }

  const char* receive_keys[] = {"receiving_addresses", "input_pubkey_sum", "tweak",
                                "shared_secret"};
  for (const char* key : receive_keys) {
    if (expected.at(key).value != actual.at(key).value) {
      errors.emplace_back(std::string("field mismatch: ") + key);
    }
  }
  if (expected.at("found_output_count").value != actual.at("found_output_count").value) {
    errors.emplace_back("field mismatch: found_output_count");
  }
  if (expected.at("detailed_outputs_available").as_bool()) {
    if (expected.at("found_outputs").value != actual.at("found_outputs").value) {
      errors.emplace_back("field mismatch: found_outputs");
    }
  }
  return errors;
}

std::string JoinErrors(const std::vector<std::string>& errors) {
  std::ostringstream out;
  for (size_t i = 0; i < errors.size(); ++i) {
    if (i != 0) {
      out << "; ";
    }
    out << errors[i];
  }
  return out.str();
}

bool LoadSemanticExpectationSummary(const std::string& expected_path,
                                    SemanticExpectationSummary* summary,
                                    std::string* error) {
  if (summary == nullptr) {
    if (error != nullptr) {
      *error = "summary output is null";
    }
    return false;
  }
  try {
    const JsonValue expected_value = ValidateSemanticResultValue(ParseJsonFile(expected_path));
    const JsonObject& expected = expected_value.as_object();

    SemanticExpectationSummary parsed;
    parsed.kind = expected.at("kind").as_string();
    parsed.semantic_status = expected.at("semantic_status").as_string();
    const JsonObject& source = expected.at("source").as_object();
    parsed.source_id = source.at("id").as_string();
    if (parsed.kind == "send") {
      for (const JsonValue& item : expected.at("acceptable_output_sets").as_array()) {
        std::vector<std::string> output_set;
        for (const JsonValue& output : item.as_array()) {
          output_set.push_back(output.as_string());
        }
        parsed.acceptable_output_sets.push_back(std::move(output_set));
      }
    } else {
      parsed.detailed_outputs_available =
          expected.at("detailed_outputs_available").as_bool();
    }
    *summary = std::move(parsed);
    return true;
  } catch (const std::exception& exception) {
    if (error != nullptr) {
      *error = exception.what();
    }
    return false;
  }
}

bool ValidateSemanticResult(const std::string& repo_root,
                            const std::vector<uint8_t>& response_json,
                            std::vector<uint8_t>* canonical_json, std::string* error) {
  (void)repo_root;
  try {
    const JsonValue raw = ParseJsonText(BytesToString(response_json));
    const JsonValue canonical = ValidateSemanticResultValue(raw);
    if (canonical_json != nullptr) {
      *canonical_json = ToBytes(SerializeJson(canonical));
    }
    return true;
  } catch (const std::exception& exception) {
    if (error) {
      *error = exception.what();
    }
    return false;
  }
}

bool CompareSemanticResultToExpected(const std::string& repo_root,
                                     const std::vector<uint8_t>& response_json,
                                     const std::string& expected_path,
                                     std::vector<uint8_t>* canonical_json,
                                     std::string* error) {
  (void)repo_root;
  try {
    const JsonValue expected = ValidateSemanticResultValue(ParseJsonFile(expected_path));
    const JsonValue actual = ValidateSemanticResultValue(ParseJsonText(BytesToString(response_json)));
    const std::vector<std::string> errors = CompareSemanticResults(expected, actual);
    if (!errors.empty()) {
      if (error) {
        *error = JoinErrors(errors);
      }
      return false;
    }
    if (canonical_json != nullptr) {
      *canonical_json = ToBytes(SerializeJson(actual));
    }
    return true;
  } catch (const std::exception& exception) {
    if (error) {
      *error = exception.what();
    }
    return false;
  }
}

}  // namespace sp_differ
