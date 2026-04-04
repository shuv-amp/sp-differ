// SPDX-License-Identifier: MIT
#include "../../ffi/sp_differ.h"
#include "../../ffi/sp_differ_semantic.h"
#include "../core/case.h"
#include "../core/io.h"
#include "../reporter/reporter.h"
#include "../runner/semantic_bridge.hpp"
#include "../runner/worker.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#ifndef SP_DIFFER_BUILD_VERSION
#define SP_DIFFER_BUILD_VERSION "0.0.0-dev"
#endif

namespace {

struct Options {
  std::vector<std::string> case_paths;
  std::string worker = "cpp";
  std::string semantic_worker = "native";
  std::string network = "mainnet";
  uint32_t silent_payment_version = 0;
  std::string json_out;
  std::string markdown_out;
  std::string suite_name = "official-mixed-suite";
  bool debug = false;
  bool help = false;
  bool benchmark_scan = false;
  uint32_t benchmark_blocks = 1000;
  uint32_t benchmark_transactions_per_block = 8;
  uint32_t benchmark_threads = 0;
  uint64_t benchmark_seed = 352;
  std::string benchmark_density = "all";
  bool export_wallet = false;
  bool check_integrity = false;
  std::string scan_secret_key_hex;
  std::string spend_secret_key_hex;
};

struct V1OutputResult {
  uint8_t status = SP_DIFFER_STATUS_INTERNAL;
  std::vector<std::string> xonly_outputs;
};

std::string UsageText() {
  return "usage: sp_differ_cli [--case <path> ...] [--worker <path|cpp|rust>] "
         "[--semantic-worker <native|native-send|native-receive|path|spdk|silent-payments|"
         "bip352|go-bip352>] [--network <mainnet|testnet|regtest|signet>] "
         "[--silent-payment-version <n>] [--json-out <path>] [--markdown-out <path>] "
         "[--suite-name <name>] [--debug]\n"
         "       sp_differ_cli --benchmark-scan [--benchmark-blocks <n>] "
         "[--benchmark-transactions-per-block <n>] [--benchmark-density <all|sparse|medium|"
         "dense>] [--benchmark-threads <n>] [--benchmark-seed <n>] "
         "[--network <mainnet|testnet|regtest|signet>] [--json-out <path>] "
         "[--markdown-out <path>]\n"
         "       sp_differ_cli --check-integrity [--json-out <path>] [--markdown-out <path>]\n"
         "       sp_differ_cli --export-wallet [--case <receive-case>] "
         "[--scan-secret-key <hex32>] [--spend-secret-key <hex32>] "
         "[--network <mainnet|testnet|regtest|signet>] [--json-out <path>] "
         "[--markdown-out <path>]";
}

bool ParseUnsigned32(const std::string& value, uint32_t* out) {
  try {
    *out = static_cast<uint32_t>(std::stoul(value));
    return true;
  } catch (...) {
    return false;
  }
}

bool ParseUnsigned64(const std::string& value, uint64_t* out) {
  try {
    *out = static_cast<uint64_t>(std::stoull(value));
    return true;
  } catch (...) {
    return false;
  }
}

bool ParseOptions(int argc, char** argv, Options* out) {
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--case") {
      if (i + 1 >= argc) {
        return false;
      }
      out->case_paths.push_back(argv[++i]);
    } else if (arg == "--worker") {
      if (i + 1 >= argc) {
        return false;
      }
      out->worker = argv[++i];
    } else if (arg == "--semantic-worker") {
      if (i + 1 >= argc) {
        return false;
      }
      out->semantic_worker = argv[++i];
    } else if (arg == "--network") {
      if (i + 1 >= argc) {
        return false;
      }
      out->network = argv[++i];
    } else if (arg == "--silent-payment-version") {
      if (i + 1 >= argc || !ParseUnsigned32(argv[++i], &out->silent_payment_version)) {
        return false;
      }
    } else if (arg == "--json-out") {
      if (i + 1 >= argc) {
        return false;
      }
      out->json_out = argv[++i];
    } else if (arg == "--markdown-out") {
      if (i + 1 >= argc) {
        return false;
      }
      out->markdown_out = argv[++i];
    } else if (arg == "--suite-name") {
      if (i + 1 >= argc) {
        return false;
      }
      out->suite_name = argv[++i];
    } else if (arg == "--benchmark-scan") {
      out->benchmark_scan = true;
    } else if (arg == "--benchmark-blocks") {
      if (i + 1 >= argc || !ParseUnsigned32(argv[++i], &out->benchmark_blocks)) {
        return false;
      }
    } else if (arg == "--benchmark-transactions-per-block") {
      if (i + 1 >= argc ||
          !ParseUnsigned32(argv[++i], &out->benchmark_transactions_per_block)) {
        return false;
      }
    } else if (arg == "--benchmark-threads") {
      if (i + 1 >= argc || !ParseUnsigned32(argv[++i], &out->benchmark_threads)) {
        return false;
      }
    } else if (arg == "--benchmark-seed") {
      if (i + 1 >= argc || !ParseUnsigned64(argv[++i], &out->benchmark_seed)) {
        return false;
      }
    } else if (arg == "--benchmark-density") {
      if (i + 1 >= argc) {
        return false;
      }
      out->benchmark_density = argv[++i];
    } else if (arg == "--export-wallet") {
      out->export_wallet = true;
    } else if (arg == "--check-integrity") {
      out->check_integrity = true;
    } else if (arg == "--scan-secret-key") {
      if (i + 1 >= argc) {
        return false;
      }
      out->scan_secret_key_hex = argv[++i];
    } else if (arg == "--spend-secret-key") {
      if (i + 1 >= argc) {
        return false;
      }
      out->spend_secret_key_hex = argv[++i];
    } else if (arg == "--debug") {
      out->debug = true;
    } else if (arg == "--help" || arg == "-h") {
      out->help = true;
      return true;
    } else {
      return false;
    }
  }

  int mode_count = 0;
  if (out->benchmark_scan) {
    mode_count += 1;
  }
  if (out->export_wallet) {
    mode_count += 1;
  }
  if (out->check_integrity) {
    mode_count += 1;
  }
  if (mode_count > 1) {
    return false;
  }
  if (mode_count == 0 && out->case_paths.empty()) {
    return false;
  }
  return true;
}

std::string EscapeJson(const std::string& value) {
  std::ostringstream out;
  for (unsigned char ch : value) {
    switch (ch) {
      case '"':
        out << "\\\"";
        break;
      case '\\':
        out << "\\\\";
        break;
      case '\b':
        out << "\\b";
        break;
      case '\f':
        out << "\\f";
        break;
      case '\n':
        out << "\\n";
        break;
      case '\r':
        out << "\\r";
        break;
      case '\t':
        out << "\\t";
        break;
      default:
        if (ch < 0x20) {
          static const char* kHex = "0123456789abcdef";
          out << "\\u00" << kHex[(ch >> 4) & 0x0F] << kHex[ch & 0x0F];
        } else {
          out << static_cast<char>(ch);
        }
        break;
    }
  }
  return out.str();
}

bool WriteTextFile(const std::string& path, const std::string& text, std::string* error) {
  std::ofstream file(path, std::ios::binary);
  if (!file) {
    if (error != nullptr) {
      *error = "unable to write output: " + path;
    }
    return false;
  }
  file << text;
  if (!file.good()) {
    if (error != nullptr) {
      *error = "unable to flush output: " + path;
    }
    return false;
  }
  return true;
}

double NanosecondsToSeconds(uint64_t nanoseconds) {
  return static_cast<double>(nanoseconds) / 1000000000.0;
}

std::string FormatDouble(double value, int precision) {
  std::ostringstream out;
  out << std::fixed << std::setprecision(precision) << value;
  return out.str();
}

bool WriteBenchmarkJson(const sp_differ::NativeScanBenchmarkReport& report,
                        const std::string& path, std::string* error) {
  std::ostringstream out;
  out << "{\n"
      << "  \"benchmark\": \"native_scan\",\n"
      << "  \"network\": \"" << EscapeJson(report.network) << "\",\n"
      << "  \"silent_payment_version\": " << report.silent_payment_version << ",\n"
      << "  \"seed\": " << report.seed << ",\n"
      << "  \"block_count\": " << report.block_count << ",\n"
      << "  \"transactions_per_block\": " << report.transactions_per_block << ",\n"
      << "  \"thread_count\": " << report.thread_count << ",\n"
      << "  \"profiles\": [\n";
  for (size_t i = 0; i < report.profiles.size(); ++i) {
    const sp_differ::NativeScanBenchmarkProfile& profile = report.profiles[i];
    const double seconds = NanosecondsToSeconds(profile.elapsed_nanoseconds);
    const double tps =
        seconds > 0.0 ? static_cast<double>(profile.transaction_count) / seconds : 0.0;
    const double outputs_per_second =
        seconds > 0.0 ? static_cast<double>(profile.output_count) / seconds : 0.0;
    out << "    {\n"
        << "      \"density\": \"" << EscapeJson(profile.density) << "\",\n"
        << "      \"outputs_per_transaction\": " << profile.outputs_per_transaction << ",\n"
        << "      \"block_count\": " << profile.block_count << ",\n"
        << "      \"transaction_count\": " << profile.transaction_count << ",\n"
        << "      \"output_count\": " << profile.output_count << ",\n"
        << "      \"matched_transaction_count\": " << profile.matched_transaction_count << ",\n"
        << "      \"found_output_count\": " << profile.found_output_count << ",\n"
        << "      \"elapsed_nanoseconds\": " << profile.elapsed_nanoseconds << ",\n"
        << "      \"transactions_per_second\": " << FormatDouble(tps, 2) << ",\n"
        << "      \"outputs_per_second\": " << FormatDouble(outputs_per_second, 2) << "\n"
        << "    }";
    if (i + 1 != report.profiles.size()) {
      out << ",";
    }
    out << "\n";
  }
  out << "  ]\n"
      << "}\n";
  return WriteTextFile(path, out.str(), error);
}

bool WriteBenchmarkMarkdown(const sp_differ::NativeScanBenchmarkReport& report,
                            const std::string& path, std::string* error) {
  std::ostringstream out;
  out << "# Native Scan Benchmark\n\n"
      << "- network: `" << report.network << "`\n"
      << "- silent payment version: `" << report.silent_payment_version << "`\n"
      << "- seed: `" << report.seed << "`\n"
      << "- blocks: `" << report.block_count << "`\n"
      << "- transactions per block: `" << report.transactions_per_block << "`\n"
      << "- threads: `" << report.thread_count << "`\n\n"
      << "| density | outputs/tx | tx count | output count | seconds | TPS | outputs/s |\n"
      << "| --- | ---: | ---: | ---: | ---: | ---: | ---: |\n";
  for (const sp_differ::NativeScanBenchmarkProfile& profile : report.profiles) {
    const double seconds = NanosecondsToSeconds(profile.elapsed_nanoseconds);
    const double tps =
        seconds > 0.0 ? static_cast<double>(profile.transaction_count) / seconds : 0.0;
    const double outputs_per_second =
        seconds > 0.0 ? static_cast<double>(profile.output_count) / seconds : 0.0;
    out << "| `" << profile.density << "` | `" << profile.outputs_per_transaction << "` | `"
        << profile.transaction_count << "` | `" << profile.output_count << "` | `"
        << FormatDouble(seconds, 3) << "` | `" << FormatDouble(tps, 2) << "` | `"
        << FormatDouble(outputs_per_second, 2) << "` |\n";
  }
  out << "\nSynthetic blocks use deterministic taproot key-path spends and native receive-side "
         "scanning.\n";
  return WriteTextFile(path, out.str(), error);
}

bool WriteWalletExportJson(const sp_differ::DescriptorWalletExport& export_data,
                           const std::string& path, std::string* error) {
  std::ostringstream out;
  out << "{\n"
      << "  \"network\": \"" << EscapeJson(export_data.network) << "\",\n"
      << "  \"silent_payment_version\": " << export_data.silent_payment_version << ",\n"
      << "  \"scan_secret_key_hex\": \"" << EscapeJson(export_data.scan_secret_key_hex)
      << "\",\n"
      << "  \"spend_secret_key_hex\": \"" << EscapeJson(export_data.spend_secret_key_hex)
      << "\",\n"
      << "  \"scan_secret_key_wif\": \"" << EscapeJson(export_data.scan_secret_key_wif)
      << "\",\n"
      << "  \"spend_secret_key_wif\": \"" << EscapeJson(export_data.spend_secret_key_wif)
      << "\",\n"
      << "  \"scan_key_expression\": \"" << EscapeJson(export_data.scan_key_expression)
      << "\",\n"
      << "  \"taproot_descriptor\": \"" << EscapeJson(export_data.taproot_descriptor)
      << "\",\n"
      << "  \"silent_payment_address\": \"" << EscapeJson(export_data.silent_payment_address)
      << "\",\n"
      << "  \"warning\": \"" << EscapeJson(export_data.warning) << "\"\n"
      << "}\n";
  return WriteTextFile(path, out.str(), error);
}

bool WriteWalletExportMarkdown(const sp_differ::DescriptorWalletExport& export_data,
                               const std::string& path, std::string* error) {
  std::ostringstream out;
  out << "# Descriptor Wallet Export\n\n"
      << "- network: `" << export_data.network << "`\n"
      << "- silent payment version: `" << export_data.silent_payment_version << "`\n"
      << "- scan secret key (hex): `" << export_data.scan_secret_key_hex << "`\n"
      << "- spend secret key (hex): `" << export_data.spend_secret_key_hex << "`\n"
      << "- scan secret key (WIF): `" << export_data.scan_secret_key_wif << "`\n"
      << "- spend secret key (WIF): `" << export_data.spend_secret_key_wif << "`\n"
      << "- scan key expression: `" << export_data.scan_key_expression << "`\n"
      << "- taproot descriptor: `" << export_data.taproot_descriptor << "`\n"
      << "- silent payment address: `" << export_data.silent_payment_address << "`\n\n"
      << export_data.warning << "\n";
  return WriteTextFile(path, out.str(), error);
}

bool IsSemverLike(const std::string& value) {
  if (value.empty()) {
    return false;
  }
  bool has_alnum = false;
  for (char ch : value) {
    if (std::isalnum(static_cast<unsigned char>(ch)) != 0) {
      has_alnum = true;
      continue;
    }
    if (ch != '.' && ch != '-' && ch != '+' && ch != '_' && ch != 'v') {
      return false;
    }
  }
  return has_alnum;
}

struct IntegrityReport {
  std::string build_version;
  bool optimized_build = false;
  uint32_t worker_abi_version = 0;
  uint32_t semantic_worker_abi_version = 0;
  uint32_t semantic_adapter_request_version = 0;
  uint32_t semantic_contract_version = 0;
  std::vector<int> supported_case_format_versions;
  bool passed = false;
  std::string detail;
};

bool WriteIntegrityJson(const IntegrityReport& report, const std::string& path,
                        std::string* error) {
  std::ostringstream out;
  out << "{\n"
      << "  \"build_version\": \"" << EscapeJson(report.build_version) << "\",\n"
      << "  \"optimized_build\": " << (report.optimized_build ? "true" : "false") << ",\n"
      << "  \"worker_abi_version\": " << report.worker_abi_version << ",\n"
      << "  \"semantic_worker_abi_version\": " << report.semantic_worker_abi_version << ",\n"
      << "  \"semantic_adapter_request_version\": " << report.semantic_adapter_request_version
      << ",\n"
      << "  \"semantic_contract_version\": " << report.semantic_contract_version << ",\n"
      << "  \"supported_case_format_versions\": [";
  for (size_t i = 0; i < report.supported_case_format_versions.size(); ++i) {
    if (i != 0) {
      out << ", ";
    }
    out << report.supported_case_format_versions[i];
  }
  out << "],\n"
      << "  \"passed\": " << (report.passed ? "true" : "false") << ",\n"
      << "  \"detail\": \"" << EscapeJson(report.detail) << "\"\n"
      << "}\n";
  return WriteTextFile(path, out.str(), error);
}

bool WriteIntegrityMarkdown(const IntegrityReport& report, const std::string& path,
                            std::string* error) {
  std::ostringstream out;
  out << "# Integrity Check\n\n"
      << "- build_version: `" << report.build_version << "`\n"
      << "- optimized_build: `" << (report.optimized_build ? "true" : "false") << "`\n"
      << "- worker_abi_version: `" << report.worker_abi_version << "`\n"
      << "- semantic_worker_abi_version: `" << report.semantic_worker_abi_version << "`\n"
      << "- semantic_adapter_request_version: `"
      << report.semantic_adapter_request_version << "`\n"
      << "- semantic_contract_version: `" << report.semantic_contract_version << "`\n"
      << "- supported_case_format_versions: `";
  for (size_t i = 0; i < report.supported_case_format_versions.size(); ++i) {
    if (i != 0) {
      out << ",";
    }
    out << report.supported_case_format_versions[i];
  }
  out << "`\n"
      << "- result: `" << (report.passed ? "passed" : "failed") << "`\n"
      << "- detail: `" << report.detail << "`\n";
  return WriteTextFile(path, out.str(), error);
}

std::string ResolveExpectationPath(const std::string& repo_root, const std::string& case_path,
                                   uint8_t case_version) {
  std::filesystem::path case_fs(case_path);
  std::filesystem::path sibling = case_fs;
  sibling.replace_extension(".expected.json");
  if (std::filesystem::exists(sibling)) {
    return sibling.string();
  }
  if (case_version == 1) {
    std::filesystem::path fallback =
        std::filesystem::path(repo_root) / "tests" / "vectors" / "bip352" / "derived" / "v2" /
        sibling.filename();
    if (std::filesystem::exists(fallback)) {
      return fallback.string();
    }
  }
  return sibling.string();
}

bool DecodeV1Output(const std::vector<uint8_t>& output, V1OutputResult* out, std::string* error) {
  if (!sp_differ::ValidateOutputPayload(output, error)) {
    return false;
  }
  out->status = output[1];
  const uint16_t count = static_cast<uint16_t>(output[2]) |
                         (static_cast<uint16_t>(output[3]) << 8);
  out->xonly_outputs.clear();
  if (out->status != SP_DIFFER_STATUS_OK) {
    return true;
  }
  out->xonly_outputs.reserve(count);
  size_t offset = 4;
  for (uint16_t i = 0; i < count; ++i) {
    if (offset + 33 > output.size()) {
      if (error != nullptr) {
        *error = "v1 output payload truncated";
      }
      return false;
    }
    out->xonly_outputs.emplace_back(
        std::string(output.begin() + static_cast<long>(offset + 1),
                    output.begin() + static_cast<long>(offset + 33)));
    offset += 33;
  }
  for (std::string& value : out->xonly_outputs) {
    static const char* kHex = "0123456789abcdef";
    std::string encoded;
    encoded.reserve(value.size() * 2);
    for (unsigned char byte : value) {
      encoded.push_back(kHex[(byte >> 4) & 0x0F]);
      encoded.push_back(kHex[byte & 0x0F]);
    }
    value = std::move(encoded);
  }
  std::sort(out->xonly_outputs.begin(), out->xonly_outputs.end());
  out->xonly_outputs.erase(
      std::unique(out->xonly_outputs.begin(), out->xonly_outputs.end()),
      out->xonly_outputs.end());
  return true;
}

bool OutputSetAccepted(const std::vector<std::string>& actual,
                       const std::vector<std::vector<std::string>>& expected_sets) {
  for (const std::vector<std::string>& candidate : expected_sets) {
    if (candidate == actual) {
      return true;
    }
  }
  return false;
}

std::string StatusName(uint8_t status) {
  switch (status) {
    case SP_DIFFER_STATUS_OK:
      return "ok";
    case SP_DIFFER_STATUS_INVALID_INPUT:
      return "invalid_input";
    case SP_DIFFER_STATUS_POINT_AT_INFINITY:
      return "point_at_infinity";
    case SP_DIFFER_STATUS_ZERO_SCALAR:
      return "zero_scalar";
    case SP_DIFFER_STATUS_INVALID_PUBKEY:
      return "invalid_pubkey";
    case SP_DIFFER_STATUS_TWEAK_OUT_OF_RANGE:
      return "tweak_out_of_range";
    case SP_DIFFER_STATUS_INTERNAL:
      return "internal";
    default:
      return "unknown";
  }
}

bool ResolveWalletExportKeys(const Options& options, std::string* scan_hex,
                             std::string* spend_hex, std::string* error) {
  if (!options.scan_secret_key_hex.empty() || !options.spend_secret_key_hex.empty()) {
    if (options.scan_secret_key_hex.empty() || options.spend_secret_key_hex.empty()) {
      if (error != nullptr) {
        *error = "wallet export requires both --scan-secret-key and --spend-secret-key";
      }
      return false;
    }
    *scan_hex = options.scan_secret_key_hex;
    *spend_hex = options.spend_secret_key_hex;
    return true;
  }

  if (options.case_paths.size() != 1) {
    if (error != nullptr) {
      *error = "wallet export requires exactly one receive case when keys are not passed";
    }
    return false;
  }

  std::vector<uint8_t> payload;
  if (!sp_differ::ReadCasePayload(options.case_paths.front(), &payload, error)) {
    return false;
  }
  sp_differ::CaseV2 parsed;
  std::string parse_error;
  if (!sp_differ::ParseCaseV2(payload, &parsed, &parse_error)) {
    if (error != nullptr) {
      *error = parse_error;
    }
    return false;
  }
  if (parsed.receiver_keys.scan_privkey.size() != 32 ||
      parsed.receiver_keys.spend_privkey.size() != 32) {
    if (error != nullptr) {
      *error = "case does not contain receiver private keys";
    }
    return false;
  }

  static const char* kHex = "0123456789abcdef";
  auto encode_hex = [&](const std::vector<uint8_t>& bytes) {
    std::string encoded;
    encoded.reserve(bytes.size() * 2);
    for (uint8_t byte : bytes) {
      encoded.push_back(kHex[(byte >> 4) & 0x0F]);
      encoded.push_back(kHex[byte & 0x0F]);
    }
    return encoded;
  };
  *scan_hex = encode_hex(parsed.receiver_keys.scan_privkey);
  *spend_hex = encode_hex(parsed.receiver_keys.spend_privkey);
  return true;
}

int VerifySuite(const Options& options) {
  const std::string repo_root = sp_differ::DetectRepoRoot(nullptr);
  sp_differ::SuiteReport report;
  report.suite_name = options.suite_name;
  report.worker = options.worker;
  report.semantic_worker = options.semantic_worker;

  bool any_failed = false;
  for (const std::string& case_path : options.case_paths) {
    sp_differ::CaseReport case_report;
    case_report.case_path = case_path;

    std::vector<uint8_t> payload;
    std::string error;
    if (!sp_differ::ReadCasePayload(case_path, &payload, &error) || payload.empty()) {
      case_report.detail = error.empty() ? "unable to read case payload" : error;
      report.cases.push_back(case_report);
      any_failed = true;
      continue;
    }

    const uint8_t version = payload[0];
    case_report.case_format_version = static_cast<int>(version);
    const std::string expected_path = ResolveExpectationPath(repo_root, case_path, version);
    case_report.expected_path = expected_path;

    sp_differ::SemanticExpectationSummary expectation;
    if (!sp_differ::LoadSemanticExpectationSummary(expected_path, &expectation, &error)) {
      case_report.detail = error;
      report.cases.push_back(case_report);
      any_failed = true;
      continue;
    }
    case_report.source_id = expectation.source_id;
    case_report.semantic_status = expectation.semantic_status;

    if (version == 1) {
      case_report.execution_mode = "v1-worker";
      case_report.implementation = options.worker;

      const std::string worker_path = sp_differ::ResolveWorkerPath(options.worker);
      sp_differ::WorkerApi api{};
      if (!sp_differ::LoadWorker(worker_path, &api, &error)) {
        case_report.detail = error;
        report.cases.push_back(case_report);
        any_failed = true;
        continue;
      }
      if (api.api_version() != SP_DIFFER_WORKER_API_VERSION) {
        sp_differ::UnloadWorker(&api);
        case_report.detail = "worker ABI version mismatch";
        report.cases.push_back(case_report);
        any_failed = true;
        continue;
      }

      std::vector<uint8_t> output;
      if (!sp_differ::RunWorker(api, payload, &output, &error)) {
        sp_differ::UnloadWorker(&api);
        case_report.detail = error;
        report.cases.push_back(case_report);
        any_failed = true;
        continue;
      }
      sp_differ::UnloadWorker(&api);

      V1OutputResult actual;
      if (!DecodeV1Output(output, &actual, &error)) {
        case_report.detail = error;
        report.cases.push_back(case_report);
        any_failed = true;
        continue;
      }

      if (expectation.semantic_status == "ok") {
        if (actual.status != SP_DIFFER_STATUS_OK) {
          case_report.detail = "worker returned non-ok status: " + StatusName(actual.status);
          report.cases.push_back(case_report);
          any_failed = true;
          continue;
        }
        if (!OutputSetAccepted(actual.xonly_outputs, expectation.acceptable_output_sets)) {
          case_report.detail = "worker outputs did not match expected acceptable output set";
          report.cases.push_back(case_report);
          any_failed = true;
          continue;
        }
      } else if (expectation.semantic_status == "zero_scalar") {
        if (actual.status != SP_DIFFER_STATUS_ZERO_SCALAR) {
          case_report.detail = "expected zero_scalar but worker returned " +
                               StatusName(actual.status);
          report.cases.push_back(case_report);
          any_failed = true;
          continue;
        }
      } else if (expectation.semantic_status == "point_at_infinity") {
        if (actual.status != SP_DIFFER_STATUS_POINT_AT_INFINITY) {
          case_report.detail = "expected point_at_infinity but worker returned " +
                               StatusName(actual.status);
          report.cases.push_back(case_report);
          any_failed = true;
          continue;
        }
      } else {
        case_report.detail =
            "v1 worker ABI cannot represent semantic status " + expectation.semantic_status;
        report.cases.push_back(case_report);
        any_failed = true;
        continue;
      }

      case_report.passed = true;
      case_report.detail = "matched expected result";
      report.cases.push_back(case_report);
      continue;
    }

    if (version != 2) {
      case_report.detail = "unsupported case format version";
      report.cases.push_back(case_report);
      any_failed = true;
      continue;
    }

    case_report.execution_mode = "semantic";
    if (options.semantic_worker == "native" || options.semantic_worker == "native-send" ||
        options.semantic_worker == "native-receive") {
      case_report.implementation = options.semantic_worker;
      if (options.semantic_worker == "native-send" && expectation.kind != "send") {
        case_report.detail = "native-send only supports send cases";
        report.cases.push_back(case_report);
        any_failed = true;
        continue;
      }
      if (options.semantic_worker == "native-receive" && expectation.kind != "receive") {
        case_report.detail = "native-receive only supports receive cases";
        report.cases.push_back(case_report);
        any_failed = true;
        continue;
      }

      std::vector<uint8_t> canonical_json;
      sp_differ::NativeSemanticOptions native_options;
      native_options.network = options.network;
      native_options.silent_payment_version = options.silent_payment_version;
      if (!sp_differ::DeriveNativeSemanticResult(repo_root, case_path, expected_path,
                                                 native_options, &canonical_json, &error)) {
        case_report.detail = error;
        report.cases.push_back(case_report);
        any_failed = true;
        continue;
      }
      if (!sp_differ::CompareSemanticResultToExpected(repo_root, canonical_json, expected_path,
                                                      nullptr, &error)) {
        case_report.detail = error;
        report.cases.push_back(case_report);
        any_failed = true;
        continue;
      }

      case_report.passed = true;
      case_report.detail = "matched expected semantic contract";
      report.cases.push_back(case_report);
      continue;
    }

    case_report.implementation = options.semantic_worker;
    sp_differ::SemanticRequestOptions request_options;
    request_options.expectation_path = expected_path;
    request_options.kind = expectation.kind;
    request_options.network = options.network;
    request_options.silent_payment_version = options.silent_payment_version;

    std::vector<uint8_t> request_json;
    if (!sp_differ::BuildSemanticRequest(repo_root, case_path, request_options, &request_json,
                                         &error)) {
      case_report.detail = error;
      report.cases.push_back(case_report);
      any_failed = true;
      continue;
    }

    const std::string worker_path = sp_differ::ResolveSemanticWorkerPath(options.semantic_worker);
    sp_differ::SemanticWorkerApi api{};
    if (!sp_differ::LoadSemanticWorker(worker_path, &api, &error)) {
      case_report.detail = error;
      report.cases.push_back(case_report);
      any_failed = true;
      continue;
    }
    if (api.api_version() != SP_DIFFER_SEMANTIC_WORKER_API_VERSION) {
      sp_differ::UnloadSemanticWorker(&api);
      case_report.detail = "semantic worker ABI version mismatch";
      report.cases.push_back(case_report);
      any_failed = true;
      continue;
    }

    std::vector<uint8_t> response_json;
    if (!sp_differ::RunSemanticWorker(api, request_json, &response_json, &error)) {
      sp_differ::UnloadSemanticWorker(&api);
      case_report.detail = error;
      report.cases.push_back(case_report);
      any_failed = true;
      continue;
    }
    sp_differ::UnloadSemanticWorker(&api);

    std::vector<uint8_t> canonical_json;
    if (!sp_differ::ValidateSemanticResult(repo_root, response_json, &canonical_json, &error) ||
        !sp_differ::CompareSemanticResultToExpected(repo_root, canonical_json, expected_path,
                                                    nullptr, &error)) {
      case_report.detail = error;
      report.cases.push_back(case_report);
      any_failed = true;
      continue;
    }

    case_report.passed = true;
    case_report.detail = "matched expected semantic contract";
    report.cases.push_back(case_report);
  }

  report.total_count = static_cast<int>(report.cases.size());
  for (const sp_differ::CaseReport& item : report.cases) {
    if (item.passed) {
      report.passed_count += 1;
    } else {
      report.failed_count += 1;
    }
  }

  std::string error;
  if (!options.json_out.empty() &&
      !sp_differ::WriteSuiteReportJson(report, options.json_out, &error)) {
    std::cerr << "FAIL: " << error << std::endl;
    return 2;
  }
  if (!options.markdown_out.empty() &&
      !sp_differ::WriteSuiteReportMarkdown(report, options.markdown_out, &error)) {
    std::cerr << "FAIL: " << error << std::endl;
    return 2;
  }

  if (any_failed) {
    std::cerr << "FAIL: " << report.failed_count << " case(s) failed" << std::endl;
    return 1;
  }

  std::cout << "OK: verified " << report.passed_count << " case(s)" << std::endl;
  return 0;
}

int RunBenchmark(const Options& options) {
  sp_differ::NativeScanBenchmarkOptions benchmark_options;
  benchmark_options.network = options.network;
  benchmark_options.silent_payment_version = options.silent_payment_version;
  benchmark_options.block_count = options.benchmark_blocks;
  benchmark_options.transactions_per_block = options.benchmark_transactions_per_block;
  benchmark_options.thread_count = options.benchmark_threads;
  benchmark_options.seed = options.benchmark_seed;
  benchmark_options.density = options.benchmark_density;

  sp_differ::NativeScanBenchmarkReport report;
  std::string error;
  if (!sp_differ::RunNativeScanBenchmark(benchmark_options, &report, &error)) {
    std::cerr << "FAIL: " << error << std::endl;
    return 2;
  }

  if (!options.json_out.empty() && !WriteBenchmarkJson(report, options.json_out, &error)) {
    std::cerr << "FAIL: " << error << std::endl;
    return 2;
  }
  if (!options.markdown_out.empty() &&
      !WriteBenchmarkMarkdown(report, options.markdown_out, &error)) {
    std::cerr << "FAIL: " << error << std::endl;
    return 2;
  }

  for (const sp_differ::NativeScanBenchmarkProfile& profile : report.profiles) {
    const double seconds = NanosecondsToSeconds(profile.elapsed_nanoseconds);
    const double tps =
        seconds > 0.0 ? static_cast<double>(profile.transaction_count) / seconds : 0.0;
    std::cout << "OK: density=" << profile.density
              << " outputs_per_tx=" << profile.outputs_per_transaction
              << " tps=" << FormatDouble(tps, 2) << " tx/s" << std::endl;
  }
  return 0;
}

int RunIntegrityCheck(const Options& options) {
  IntegrityReport report;
  report.build_version = SP_DIFFER_BUILD_VERSION;
#ifdef NDEBUG
  report.optimized_build = true;
#else
  report.optimized_build = false;
#endif
  report.worker_abi_version = SP_DIFFER_WORKER_API_VERSION;
  report.semantic_worker_abi_version = SP_DIFFER_SEMANTIC_WORKER_API_VERSION;
  report.semantic_adapter_request_version = sp_differ::SemanticAdapterRequestVersion();
  report.semantic_contract_version = sp_differ::SemanticContractVersion();
  report.supported_case_format_versions = {1, 2};

  if (!IsSemverLike(report.build_version)) {
    report.detail = "build version is empty or malformed";
  } else if (report.semantic_adapter_request_version != 1) {
    report.detail = "unsupported semantic adapter request version";
  } else if (report.semantic_contract_version != 1) {
    report.detail = "unsupported semantic contract version";
  } else if (report.supported_case_format_versions != std::vector<int>({1, 2})) {
    report.detail = "unsupported case format set";
  } else {
    report.passed = true;
    report.detail = "build version and protocol compatibility checks passed";
  }

  std::string error;
  if (!options.json_out.empty() && !WriteIntegrityJson(report, options.json_out, &error)) {
    std::cerr << "FAIL: " << error << std::endl;
    return 2;
  }
  if (!options.markdown_out.empty() &&
      !WriteIntegrityMarkdown(report, options.markdown_out, &error)) {
    std::cerr << "FAIL: " << error << std::endl;
    return 2;
  }
  if (!report.passed) {
    std::cerr << "FAIL: " << report.detail << std::endl;
    return 1;
  }
  std::cout << "OK: " << report.detail << " (build_version=" << report.build_version << ")"
            << std::endl;
  return 0;
}

int RunWalletExport(const Options& options) {
  if (options.json_out.empty() && options.markdown_out.empty()) {
    std::cerr << "FAIL: wallet export requires --json-out or --markdown-out" << std::endl;
    return 2;
  }

  std::string scan_secret_key_hex;
  std::string spend_secret_key_hex;
  std::string error;
  if (!ResolveWalletExportKeys(options, &scan_secret_key_hex, &spend_secret_key_hex, &error)) {
    std::cerr << "FAIL: " << error << std::endl;
    return 2;
  }

  sp_differ::DescriptorWalletExport export_data;
  if (!sp_differ::ExportDescriptorWallet(options.network, options.silent_payment_version,
                                         scan_secret_key_hex, spend_secret_key_hex,
                                         &export_data, &error)) {
    std::cerr << "FAIL: " << error << std::endl;
    return 2;
  }

  if (!options.json_out.empty() && !WriteWalletExportJson(export_data, options.json_out, &error)) {
    std::cerr << "FAIL: " << error << std::endl;
    return 2;
  }
  if (!options.markdown_out.empty() &&
      !WriteWalletExportMarkdown(export_data, options.markdown_out, &error)) {
    std::cerr << "FAIL: " << error << std::endl;
    return 2;
  }

  std::cout << "OK: wallet export generated for network " << export_data.network;
  if (!options.json_out.empty()) {
    std::cout << " json=" << options.json_out;
  }
  if (!options.markdown_out.empty()) {
    std::cout << " markdown=" << options.markdown_out;
  }
  std::cout << std::endl;
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  Options options;
  if (!ParseOptions(argc, argv, &options)) {
    std::cerr << UsageText() << std::endl;
    return 2;
  }
  if (options.help) {
    std::cout << UsageText() << std::endl;
    return 0;
  }
  if (options.benchmark_scan) {
    return RunBenchmark(options);
  }
  if (options.check_integrity) {
    return RunIntegrityCheck(options);
  }
  if (options.export_wallet) {
    return RunWalletExport(options);
  }
  return VerifySuite(options);
}
