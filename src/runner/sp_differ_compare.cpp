#include "../../ffi/sp_differ.h"
#include "../core/io.h"
#include "../core/validate.h"
#include "worker.h"

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

namespace {

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
  std::string case_path;
  std::string left_worker = "cpp";
  std::string right_worker = "rust";

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
    } else if (arg == "--help" || arg == "-h") {
      std::cout << "usage: sp_differ_compare <case> [--left <path|cpp|rust>] [--right <path|cpp|rust>]"
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

  if (!sp_differ::ValidateCaseHeader(input, &error)) {
    std::cerr << "FAIL: " << error << std::endl;
    return 2;
  }

  std::string left_path = sp_differ::ResolveWorkerPath(left_worker);
  std::string right_path = sp_differ::ResolveWorkerPath(right_worker);

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
