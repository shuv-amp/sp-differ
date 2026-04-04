// SPDX-License-Identifier: MIT
#include "../../ffi/sp_differ.h"
#include "../../ffi/sp_differ_semantic.h"
#include "../core/case.h"
#include "../core/io.h"
#include "semantic_bridge.hpp"
#include "worker.h"

#include <cstdint>
#include <iostream>
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

}  // namespace

int main(int argc, char** argv) {
  std::string case_path;
  std::string worker_selector;
  std::string expectation_path;
  std::string semantic_kind = "auto";
  std::string semantic_network = "mainnet";
  uint32_t silent_payment_version = 0;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--worker") {
      if (i + 1 >= argc) {
        std::cerr << "FAIL: --worker requires a path" << std::endl;
        return 2;
      }
      worker_selector = argv[++i];
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
          << "usage: sp_differ_runner <case> [--worker <path|cpp|rust|spdk|silent-payments|bip352|go-bip352>] [--expectation <path>] [--semantic-kind <auto|send|receive>] [--network <mainnet|testnet|regtest|signet>] [--silent-payment-version <n>]"
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

  // v1 cases use the original byte-worker ABI. v2 cases are routed through
  // the semantic request/response contract so adapters and semantic workers
  // share the same expectation logic.
  const uint8_t version = input[0];
  if (version == 1) {
    sp_differ::Case parsed;
    if (!sp_differ::ParseCaseV1(input, &parsed, &error)) {
      std::cerr << "FAIL: " << error << std::endl;
      return 2;
    }

    const std::string worker_path = sp_differ::ResolveWorkerPath(
        worker_selector.empty() ? "cpp" : worker_selector);
    sp_differ::WorkerApi api{};
    if (!sp_differ::LoadWorker(worker_path, &api, &error)) {
      std::cerr << "FAIL: " << error << std::endl;
      return 2;
    }

    if (api.api_version() != SP_DIFFER_WORKER_API_VERSION) {
      sp_differ::UnloadWorker(&api);
      std::cerr << "FAIL: worker ABI version mismatch" << std::endl;
      return 2;
    }

    std::vector<uint8_t> output;
    if (!sp_differ::RunWorker(api, input, &output, &error)) {
      sp_differ::UnloadWorker(&api);
      std::cerr << "FAIL: " << error << std::endl;
      return 2;
    }

    sp_differ::UnloadWorker(&api);

    if (!sp_differ::ValidateOutputPayload(output, &error)) {
      std::cerr << "FAIL: " << error << std::endl;
      return 2;
    }

    std::cout << "OK: output valid" << std::endl;
    return 0;
  }

  if (version == 2) {
    sp_differ::CaseV2 parsed;
    if (!sp_differ::ParseCaseV2(input, &parsed, &error)) {
      std::cerr << "FAIL: " << error << std::endl;
      return 2;
    }

    // Semantic requests resolve expectation sidecars and vendored reference data
    // relative to the repository root so the runner does not depend on cwd.
    const std::string repo_root = sp_differ::DetectRepoRoot(argv[0]);
    sp_differ::SemanticRequestOptions request_options;
    request_options.expectation_path = expectation_path;
    request_options.kind = semantic_kind;
    request_options.network = semantic_network;
    request_options.silent_payment_version = silent_payment_version;

    std::vector<uint8_t> request_json;
    if (!sp_differ::BuildSemanticRequest(repo_root, case_path, request_options,
                                         &request_json, &error)) {
      std::cerr << "FAIL: " << error << std::endl;
      return 2;
    }

    const std::string worker_path = sp_differ::ResolveSemanticWorkerPath(
        worker_selector.empty() ? "spdk" : worker_selector);
    sp_differ::SemanticWorkerApi api{};
    if (!sp_differ::LoadSemanticWorker(worker_path, &api, &error)) {
      std::cerr << "FAIL: " << error << std::endl;
      return 2;
    }

    if (api.api_version() != SP_DIFFER_SEMANTIC_WORKER_API_VERSION) {
      sp_differ::UnloadSemanticWorker(&api);
      std::cerr << "FAIL: semantic worker ABI version mismatch" << std::endl;
      return 2;
    }

    std::vector<uint8_t> output;
    if (!sp_differ::RunSemanticWorker(api, request_json, &output, &error)) {
      sp_differ::UnloadSemanticWorker(&api);
      std::cerr << "FAIL: " << error << std::endl;
      return 2;
    }

    sp_differ::UnloadSemanticWorker(&api);

    std::vector<uint8_t> canonical_output;
    if (!sp_differ::ValidateSemanticResult(repo_root, output, &canonical_output,
                                           &error)) {
      std::cerr << "FAIL: " << error << std::endl;
      return 2;
    }

    std::cout << "OK: semantic output valid" << std::endl;
    return 0;
  }

  std::cerr << "FAIL: unsupported version: " << static_cast<int>(version) << std::endl;
  return 2;
}
