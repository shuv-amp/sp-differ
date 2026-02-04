#include "../../ffi/sp_differ.h"
#include "../core/io.h"
#include "../core/validate.h"
#include "worker.h"

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

int main(int argc, char** argv) {
  std::string case_path;
  std::string worker_path = sp_differ::DefaultCppWorkerPath();

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--worker") {
      if (i + 1 >= argc) {
        std::cerr << "FAIL: --worker requires a path" << std::endl;
        return 2;
      }
      worker_path = sp_differ::ResolveWorkerPath(argv[++i]);
    } else if (arg == "--help" || arg == "-h") {
      std::cout << "usage: sp_differ_runner <case> [--worker <path|cpp|rust>]" << std::endl;
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

  if (!sp_differ::ValidateCaseHeader(input, &error)) {
    std::cerr << "FAIL: " << error << std::endl;
    return 2;
  }

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
