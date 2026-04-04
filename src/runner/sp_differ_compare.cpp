// SPDX-License-Identifier: MIT
#include "../../ffi/sp_differ.h"
#include "../../ffi/sp_differ_semantic.h"
#include "../core/case.h"
#include "../core/io.h"
#include "semantic_bridge.hpp"
#include "worker.h"

#include <cctype>
#include <cstdint>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

bool ParseUnsignedArg(const char* value, uint32_t* out) {
  try {
    *out = static_cast<uint32_t>(std::stoul(value));
    return true;
  } catch (...) {
    return false;
  }
}

struct CompareResult {
  int exit_code = 0;
  std::vector<uint8_t> canonical_output;
  std::string error;
};

struct SemanticCompareResult {
  bool matches_expectation = false;
  std::vector<uint8_t> canonical_output;
  std::string error;
};

constexpr int kExitCodeMatch = 0;
constexpr int kExitCodeValidMismatch = 1;
constexpr int kExitCodeBothOracleMismatch = 9;

bool ReadTextFile(const std::string& path, std::string* text) {
  std::ifstream file(path);
  if (!file) {
    return false;
  }
  std::ostringstream out;
  out << file.rdbuf();
  *text = out.str();
  return true;
}

void SkipJsonWhitespace(const std::string& json, size_t* pos) {
  while (*pos < json.size() &&
         std::isspace(static_cast<unsigned char>(json[*pos])) != 0) {
    ++(*pos);
  }
}

bool ParseJsonStringLiteral(const std::string& json, size_t* pos,
                            std::string* value) {
  if (*pos >= json.size() || json[*pos] != '"') {
    return false;
  }
  ++(*pos);
  if (value != nullptr) {
    value->clear();
  }
  while (*pos < json.size()) {
    const char ch = json[*pos];
    if (ch == '"') {
      ++(*pos);
      return true;
    }
    if (ch == '\\') {
      ++(*pos);
      if (*pos >= json.size()) {
        return false;
      }
      const char escaped = json[*pos];
      if (value != nullptr) {
        switch (escaped) {
          case '"':
          case '\\':
          case '/':
            value->push_back(escaped);
            break;
          case 'b':
            value->push_back('\b');
            break;
          case 'f':
            value->push_back('\f');
            break;
          case 'n':
            value->push_back('\n');
            break;
          case 'r':
            value->push_back('\r');
            break;
          case 't':
            value->push_back('\t');
            break;
          case 'u':
            break;
          default:
            return false;
        }
      } else if (escaped != '"' && escaped != '\\' && escaped != '/' &&
                 escaped != 'b' && escaped != 'f' && escaped != 'n' &&
                 escaped != 'r' && escaped != 't' && escaped != 'u') {
        return false;
      }
      if (escaped == 'u') {
        for (int i = 0; i < 4; ++i) {
          ++(*pos);
          if (*pos >= json.size() ||
              std::isxdigit(static_cast<unsigned char>(json[*pos])) == 0) {
            return false;
          }
        }
        if (value != nullptr) {
          value->push_back('?');
        }
      }
      ++(*pos);
      continue;
    }
    if (value != nullptr) {
      value->push_back(ch);
    }
    ++(*pos);
  }
  return false;
}

bool SkipJsonValue(const std::string& json, size_t* pos) {
  SkipJsonWhitespace(json, pos);
  if (*pos >= json.size()) {
    return false;
  }
  if (json[*pos] == '"') {
    return ParseJsonStringLiteral(json, pos, nullptr);
  }
  if (json[*pos] == '{') {
    ++(*pos);
    SkipJsonWhitespace(json, pos);
    if (*pos < json.size() && json[*pos] == '}') {
      ++(*pos);
      return true;
    }
    while (*pos < json.size()) {
      if (!ParseJsonStringLiteral(json, pos, nullptr)) {
        return false;
      }
      SkipJsonWhitespace(json, pos);
      if (*pos >= json.size() || json[*pos] != ':') {
        return false;
      }
      ++(*pos);
      if (!SkipJsonValue(json, pos)) {
        return false;
      }
      SkipJsonWhitespace(json, pos);
      if (*pos >= json.size()) {
        return false;
      }
      if (json[*pos] == '}') {
        ++(*pos);
        return true;
      }
      if (json[*pos] != ',') {
        return false;
      }
      ++(*pos);
      SkipJsonWhitespace(json, pos);
    }
    return false;
  }
  if (json[*pos] == '[') {
    ++(*pos);
    SkipJsonWhitespace(json, pos);
    if (*pos < json.size() && json[*pos] == ']') {
      ++(*pos);
      return true;
    }
    while (*pos < json.size()) {
      if (!SkipJsonValue(json, pos)) {
        return false;
      }
      SkipJsonWhitespace(json, pos);
      if (*pos >= json.size()) {
        return false;
      }
      if (json[*pos] == ']') {
        ++(*pos);
        return true;
      }
      if (json[*pos] != ',') {
        return false;
      }
      ++(*pos);
      SkipJsonWhitespace(json, pos);
    }
    return false;
  }

  const size_t start = *pos;
  while (*pos < json.size()) {
    const char ch = json[*pos];
    if (ch == ',' || ch == '}' || ch == ']' ||
        std::isspace(static_cast<unsigned char>(ch)) != 0) {
      break;
    }
    ++(*pos);
  }
  return *pos > start;
}

// Only top-level fixture fields count here. Nested copies are ignored so
// auxiliary metadata cannot mask a mismatch in the canonical fixture fields.
bool FindTopLevelJsonField(const std::string& json, const std::string& field,
                           size_t* value_start, size_t* value_end) {
  size_t pos = 0;
  SkipJsonWhitespace(json, &pos);
  if (pos >= json.size() || json[pos] != '{') {
    return false;
  }
  ++pos;
  SkipJsonWhitespace(json, &pos);
  if (pos < json.size() && json[pos] == '}') {
    return false;
  }
  while (pos < json.size()) {
    std::string key;
    if (!ParseJsonStringLiteral(json, &pos, &key)) {
      return false;
    }
    SkipJsonWhitespace(json, &pos);
    if (pos >= json.size() || json[pos] != ':') {
      return false;
    }
    ++pos;
    SkipJsonWhitespace(json, &pos);
    const size_t start = pos;
    if (!SkipJsonValue(json, &pos)) {
      return false;
    }
    if (key == field) {
      *value_start = start;
      *value_end = pos;
      return true;
    }
    SkipJsonWhitespace(json, &pos);
    if (pos >= json.size()) {
      return false;
    }
    if (json[pos] == '}') {
      return false;
    }
    if (json[pos] != ',') {
      return false;
    }
    ++pos;
    SkipJsonWhitespace(json, &pos);
  }
  return false;
}

bool ExtractJsonStringField(const std::string& json, const std::string& field,
                            std::string* value) {
  size_t value_start = 0;
  size_t value_end = 0;
  if (!FindTopLevelJsonField(json, field, &value_start, &value_end)) {
    return false;
  }
  size_t pos = value_start;
  if (!ParseJsonStringLiteral(json, &pos, value)) {
    return false;
  }
  SkipJsonWhitespace(json, &pos);
  return pos == value_end;
}

bool ExtractJsonIntField(const std::string& json, const std::string& field, int* value) {
  size_t value_start = 0;
  size_t value_end = 0;
  if (!FindTopLevelJsonField(json, field, &value_start, &value_end)) {
    return false;
  }
  size_t i = value_start;
  while (i < value_end && std::isspace(static_cast<unsigned char>(json[i])) != 0) {
    ++i;
  }
  bool negative = false;
  if (i < value_end && json[i] == '-') {
    negative = true;
    ++i;
  }
  if (i >= value_end || !std::isdigit(static_cast<unsigned char>(json[i]))) {
    return false;
  }
  int parsed = 0;
  while (i < value_end && std::isdigit(static_cast<unsigned char>(json[i]))) {
    parsed = parsed * 10 + (json[i] - '0');
    ++i;
  }
  while (i < value_end && std::isspace(static_cast<unsigned char>(json[i])) != 0) {
    ++i;
  }
  if (i != value_end) {
    return false;
  }
  *value = negative ? -parsed : parsed;
  return true;
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

bool DecodeHex(const std::string& hex, std::vector<uint8_t>* out) {
  if (hex.size() % 2 != 0) {
    return false;
  }
  out->clear();
  out->reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    const int hi = HexValue(hex[i]);
    const int lo = HexValue(hex[i + 1]);
    if (hi < 0 || lo < 0) {
      return false;
    }
    out->push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return true;
}

std::string ToHex(const std::vector<uint8_t>& data) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (uint8_t byte : data) {
    out << std::setw(2) << static_cast<int>(byte);
  }
  return out.str();
}

bool LoadFixtureCompareResult(const std::string& path, CompareResult* result,
                              std::string* error) {
  std::string json;
  if (!ReadTextFile(path, &json)) {
    *error = "unable to read fixture: " + path;
    return false;
  }

  int parsed_exit_code = 0;
  if (ExtractJsonIntField(json, "exit_code", &parsed_exit_code)) {
    result->exit_code = parsed_exit_code;
  }

  std::string canonical_output_hex;
  if (!ExtractJsonStringField(json, "canonical_output", &canonical_output_hex)) {
    *error = "fixture is missing canonical_output: " + path;
    return false;
  }

  if (!canonical_output_hex.empty() &&
      !DecodeHex(canonical_output_hex, &result->canonical_output)) {
    *error = "fixture canonical_output is not valid hex: " + path;
    return false;
  }

  return true;
}

int EmitComparisonDecision(const CompareResult& worker_a, const CompareResult& worker_b) {
  if (worker_a.exit_code != 0 && worker_b.exit_code != 0) {
    std::cerr << "BOTH_CRASH" << std::endl;
    return 2;
  }
  if (worker_a.exit_code != 0) {
    std::cerr << "WORKER_A_CRASH" << std::endl;
    return 3;
  }
  if (worker_b.exit_code != 0) {
    std::cerr << "WORKER_B_CRASH" << std::endl;
    return 4;
  }
  if (worker_a.canonical_output.empty()) {
    std::cerr << "WORKER_A_EMPTY_OUTPUT" << std::endl;
    return 5;
  }
  if (worker_b.canonical_output.empty()) {
    std::cerr << "WORKER_B_EMPTY_OUTPUT" << std::endl;
    return 6;
  }
  if (worker_a.canonical_output != worker_b.canonical_output) {
    std::cerr << "VALID_MISMATCH" << std::endl;
    std::cerr << "worker_a_hex=" << ToHex(worker_a.canonical_output) << std::endl;
    std::cerr << "worker_b_hex=" << ToHex(worker_b.canonical_output) << std::endl;
    return 1;
  }

  std::cout << "MATCH" << std::endl;
  return kExitCodeMatch;
}

// Distinguish a real differential mismatch from the case where both workers
// disagree with the oracle in the same way. Those are different failures.
int EmitSemanticComparisonDecision(const SemanticCompareResult& worker_a,
                                   const SemanticCompareResult& worker_b) {
  if (worker_a.matches_expectation && worker_b.matches_expectation) {
    std::cout << "MATCH" << std::endl;
    return kExitCodeMatch;
  }

  if (!worker_a.matches_expectation && !worker_a.error.empty()) {
    std::cerr << "worker_a_error=" << worker_a.error << std::endl;
  }
  if (!worker_b.matches_expectation && !worker_b.error.empty()) {
    std::cerr << "worker_b_error=" << worker_b.error << std::endl;
  }

  if (worker_a.matches_expectation != worker_b.matches_expectation ||
      worker_a.canonical_output != worker_b.canonical_output) {
    std::cerr << "VALID_MISMATCH" << std::endl;
    std::cerr << "worker_a_hex=" << ToHex(worker_a.canonical_output) << std::endl;
    std::cerr << "worker_b_hex=" << ToHex(worker_b.canonical_output) << std::endl;
    return kExitCodeValidMismatch;
  }

  std::cerr << "BOTH_ORACLE_MISMATCH" << std::endl;
  return kExitCodeBothOracleMismatch;
}

void PrintMismatch(const std::vector<uint8_t>& left, const std::vector<uint8_t>& right) {
  std::cerr << "MISMATCH: outputs differ" << std::endl;
  std::cerr << "  left_len: " << left.size() << std::endl;
  std::cerr << "  right_len: " << right.size() << std::endl;

  size_t min_len = left.size() < right.size() ? left.size() : right.size();
  for (size_t i = 0; i < min_len; ++i) {
    if (left[i] != right[i]) {
      std::cerr << "  first_diff: " << i << " left=0x" << std::hex << std::setw(2)
                << std::setfill('0') << static_cast<int>(left[i]) << " right=0x"
                << std::setw(2) << static_cast<int>(right[i]) << std::dec << std::endl;
      return;
    }
  }

  if (left.size() != right.size()) {
    std::cerr << "  first_diff: " << min_len << " (length mismatch)" << std::endl;
  }
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 3 && argv[1][0] != '-' && argv[2][0] != '-') {
    CompareResult worker_a;
    CompareResult worker_b;
    std::string error;

    if (!LoadFixtureCompareResult(argv[1], &worker_a, &error)) {
      std::cerr << "FAIL: " << error << std::endl;
      return 2;
    }
    if (!LoadFixtureCompareResult(argv[2], &worker_b, &error)) {
      std::cerr << "FAIL: " << error << std::endl;
      return 2;
    }

    return EmitComparisonDecision(worker_a, worker_b);
  }

  std::string case_path;
  std::string left_worker;
  std::string right_worker;
  std::string expectation_path;
  std::string semantic_kind = "auto";
  std::string semantic_network = "mainnet";
  uint32_t silent_payment_version = 0;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--left") {
      if (i + 1 >= argc) {
        std::cerr << "FAIL: --left requires a value" << std::endl;
        return 2;
      }
      left_worker = argv[++i];
    } else if (arg == "--right") {
      if (i + 1 >= argc) {
        std::cerr << "FAIL: --right requires a value" << std::endl;
        return 2;
      }
      right_worker = argv[++i];
    } else if (arg == "--expectation") {
      if (i + 1 >= argc) {
        std::cerr << "FAIL: --expectation requires a path" << std::endl;
        return 2;
      }
      expectation_path = argv[++i];
    } else if (arg == "--semantic-kind") {
      if (i + 1 >= argc) {
        std::cerr << "FAIL: --semantic-kind requires a value" << std::endl;
        return 2;
      }
      semantic_kind = argv[++i];
    } else if (arg == "--network") {
      if (i + 1 >= argc) {
        std::cerr << "FAIL: --network requires a value" << std::endl;
        return 2;
      }
      semantic_network = argv[++i];
    } else if (arg == "--silent-payment-version") {
      if (i + 1 >= argc) {
        std::cerr << "FAIL: --silent-payment-version requires a value" << std::endl;
        return 2;
      }
      if (!ParseUnsignedArg(argv[++i], &silent_payment_version)) {
        std::cerr << "FAIL: invalid --silent-payment-version value" << std::endl;
        return 2;
      }
    } else if (arg == "--help" || arg == "-h") {
      std::cout
          << "usage: sp_differ_compare <case> [--left <path|cpp|rust|spdk|silent-payments|bip352|go-bip352>] [--right <path|cpp|rust|spdk|silent-payments|bip352|go-bip352>] [--expectation <path>] [--semantic-kind <auto|send|receive>] [--network <mainnet|testnet|regtest>] [--silent-payment-version <n>]"
          << std::endl;
      return 0;
    } else if (case_path.empty()) {
      case_path = arg;
    } else {
      std::cerr << "FAIL: unexpected argument" << std::endl;
      return 2;
    }
  }

  if (case_path.empty()) {
    std::cerr << "FAIL: case path required" << std::endl;
    return 2;
  }

  std::vector<uint8_t> input;
  std::string error;
  if (!sp_differ::ReadCasePayload(case_path, &input, &error)) {
    std::cerr << "FAIL: " << error << std::endl;
    return 2;
  }
  if (input.empty()) {
    std::cerr << "FAIL: empty case payload" << std::endl;
    return 2;
  }

  const uint8_t version = input[0];
  if (version == 1) {
    sp_differ::Case parsed;
    if (!sp_differ::ParseCaseV1(input, &parsed, &error)) {
      std::cerr << "FAIL: " << error << std::endl;
      return 2;
    }

    std::string left_path = sp_differ::ResolveWorkerPath(left_worker.empty() ? "cpp" : left_worker);
    std::string right_path = sp_differ::ResolveWorkerPath(right_worker.empty() ? "rust" : right_worker);

    sp_differ::WorkerApi left_api{};
    if (!sp_differ::LoadWorker(left_path, &left_api, &error)) {
      std::cerr << "FAIL: " << error << std::endl;
      return 2;
    }

    if (left_api.api_version() != SP_DIFFER_WORKER_API_VERSION) {
      sp_differ::UnloadWorker(&left_api);
      std::cerr << "FAIL: left worker ABI version mismatch" << std::endl;
      return 2;
    }

    sp_differ::WorkerApi right_api{};
    if (!sp_differ::LoadWorker(right_path, &right_api, &error)) {
      sp_differ::UnloadWorker(&left_api);
      std::cerr << "FAIL: " << error << std::endl;
      return 2;
    }

    if (right_api.api_version() != SP_DIFFER_WORKER_API_VERSION) {
      sp_differ::UnloadWorker(&left_api);
      sp_differ::UnloadWorker(&right_api);
      std::cerr << "FAIL: right worker ABI version mismatch" << std::endl;
      return 2;
    }

    std::vector<uint8_t> left_output;
    if (!sp_differ::RunWorker(left_api, input, &left_output, &error)) {
      sp_differ::UnloadWorker(&left_api);
      sp_differ::UnloadWorker(&right_api);
      std::cerr << "FAIL: " << error << std::endl;
      return 2;
    }

    std::vector<uint8_t> right_output;
    if (!sp_differ::RunWorker(right_api, input, &right_output, &error)) {
      sp_differ::UnloadWorker(&left_api);
      sp_differ::UnloadWorker(&right_api);
      std::cerr << "FAIL: " << error << std::endl;
      return 2;
    }

    sp_differ::UnloadWorker(&left_api);
    sp_differ::UnloadWorker(&right_api);

    if (!sp_differ::ValidateOutputPayload(left_output, &error)) {
      std::cerr << "FAIL: left output invalid" << std::endl;
      return 2;
    }

    if (!sp_differ::ValidateOutputPayload(right_output, &error)) {
      std::cerr << "FAIL: right output invalid" << std::endl;
      return 2;
    }

    if (left_output != right_output) {
      PrintMismatch(left_output, right_output);
      return 2;
    }

    std::cout << "OK: outputs match" << std::endl;
    return 0;
  }

  if (version == 2) {
    sp_differ::CaseV2 parsed;
    if (!sp_differ::ParseCaseV2(input, &parsed, &error)) {
      std::cerr << "FAIL: " << error << std::endl;
      return 2;
    }

    // Validate each semantic result against the contract before comparing the
    // two workers. Matching each other is not enough if both violate the oracle.
    const std::string repo_root = sp_differ::DetectRepoRoot(argv[0]);
    std::string resolved_expectation = expectation_path;
    if (resolved_expectation.empty()) {
      resolved_expectation = sp_differ::DefaultExpectationPath(case_path);
    }
    if (!std::filesystem::exists(resolved_expectation)) {
      std::cerr << "FAIL: expectation file required for v2 semantic comparison: "
                << resolved_expectation << std::endl;
      return 2;
    }

    sp_differ::SemanticRequestOptions request_options;
    request_options.expectation_path = resolved_expectation;
    request_options.kind = semantic_kind;
    request_options.network = semantic_network;
    request_options.silent_payment_version = silent_payment_version;

    std::vector<uint8_t> request_json;
    if (!sp_differ::BuildSemanticRequest(repo_root, case_path, request_options,
                                         &request_json, &error)) {
      std::cerr << "FAIL: " << error << std::endl;
      return 2;
    }

    std::string left_path = sp_differ::ResolveSemanticWorkerPath(
        left_worker.empty() ? "spdk" : left_worker);
    std::string right_path = sp_differ::ResolveSemanticWorkerPath(
        right_worker.empty() ? "silent-payments" : right_worker);

    sp_differ::SemanticWorkerApi left_api{};
    if (!sp_differ::LoadSemanticWorker(left_path, &left_api, &error)) {
      std::cerr << "FAIL: " << error << std::endl;
      return 2;
    }
    if (left_api.api_version() != SP_DIFFER_SEMANTIC_WORKER_API_VERSION) {
      sp_differ::UnloadSemanticWorker(&left_api);
      std::cerr << "FAIL: left semantic worker ABI version mismatch" << std::endl;
      return 2;
    }

    sp_differ::SemanticWorkerApi right_api{};
    if (!sp_differ::LoadSemanticWorker(right_path, &right_api, &error)) {
      sp_differ::UnloadSemanticWorker(&left_api);
      std::cerr << "FAIL: " << error << std::endl;
      return 2;
    }
    if (right_api.api_version() != SP_DIFFER_SEMANTIC_WORKER_API_VERSION) {
      sp_differ::UnloadSemanticWorker(&left_api);
      sp_differ::UnloadSemanticWorker(&right_api);
      std::cerr << "FAIL: right semantic worker ABI version mismatch" << std::endl;
      return 2;
    }

    std::vector<uint8_t> left_output;
    if (!sp_differ::RunSemanticWorker(left_api, request_json, &left_output, &error)) {
      sp_differ::UnloadSemanticWorker(&left_api);
      sp_differ::UnloadSemanticWorker(&right_api);
      std::cerr << "FAIL: left semantic worker run failed: " << error << std::endl;
      return 2;
    }

    std::vector<uint8_t> right_output;
    if (!sp_differ::RunSemanticWorker(right_api, request_json, &right_output, &error)) {
      sp_differ::UnloadSemanticWorker(&left_api);
      sp_differ::UnloadSemanticWorker(&right_api);
      std::cerr << "FAIL: right semantic worker run failed: " << error << std::endl;
      return 2;
    }

    sp_differ::UnloadSemanticWorker(&left_api);
    sp_differ::UnloadSemanticWorker(&right_api);

    std::vector<uint8_t> left_canonical;
    std::vector<uint8_t> right_canonical;
    if (!sp_differ::ValidateSemanticResult(repo_root, left_output, &left_canonical,
                                           &error)) {
      std::cerr << "FAIL: left semantic output invalid: " << error << std::endl;
      return 2;
    }
    if (!sp_differ::ValidateSemanticResult(repo_root, right_output, &right_canonical,
                                           &error)) {
      std::cerr << "FAIL: right semantic output invalid: " << error << std::endl;
      return 2;
    }

    std::string left_error;
    std::string right_error;
    std::vector<uint8_t> ignored_left_canonical;
    std::vector<uint8_t> ignored_right_canonical;
    const bool left_ok = sp_differ::CompareSemanticResultToExpected(
        repo_root, left_output, resolved_expectation, &ignored_left_canonical,
        &left_error);
    const bool right_ok = sp_differ::CompareSemanticResultToExpected(
        repo_root, right_output, resolved_expectation, &ignored_right_canonical,
        &right_error);

    SemanticCompareResult worker_a;
    worker_a.matches_expectation = left_ok;
    worker_a.canonical_output = std::move(left_canonical);
    worker_a.error = left_error;

    SemanticCompareResult worker_b;
    worker_b.matches_expectation = right_ok;
    worker_b.canonical_output = std::move(right_canonical);
    worker_b.error = right_error;

    return EmitSemanticComparisonDecision(worker_a, worker_b);
  }

  std::cerr << "FAIL: unsupported version: " << static_cast<int>(version) << std::endl;
  return 2;
}
