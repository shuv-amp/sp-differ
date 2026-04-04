#include "../src/core/io.h"
#include "../src/runner/semantic_bridge.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

namespace {

std::string HexEncode(const uint8_t* data, size_t size) {
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.reserve(size * 2);
  for (size_t i = 0; i < size; ++i) {
    out.push_back(kHex[(data[i] >> 4) & 0x0F]);
    out.push_back(kHex[data[i] & 0x0F]);
  }
  return out;
}

std::string WriteTemporaryFile(const uint8_t* data, size_t size) {
#if defined(_WIN32)
  (void)data;
  (void)size;
  return std::string();
#else
  char path[] = "/tmp/sp_differ_fuzz_XXXXXX";
  const int fd = mkstemp(path);
  if (fd < 0) {
    return std::string();
  }
  size_t written = 0;
  while (written < size) {
    const ssize_t rc = write(fd, data + written, size - written);
    if (rc <= 0) {
      close(fd);
      unlink(path);
      return std::string();
    }
    written += static_cast<size_t>(rc);
  }
  close(fd);
  return std::string(path);
#endif
}

std::string WriteTemporaryTextFile(const std::string& text) {
  return WriteTemporaryFile(reinterpret_cast<const uint8_t*>(text.data()), text.size());
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (data == nullptr || size == 0) {
    return 0;
  }

  const size_t first = size / 3;
  const size_t second = (size - first) / 2;
  const uint8_t* semantic_bytes = data;
  const size_t semantic_size = first;
  const uint8_t* expected_bytes = data + first;
  const size_t expected_size = second;
  const uint8_t* output_bytes = data + first + second;
  const size_t output_size = size - first - second;

  std::string error;
  std::vector<uint8_t> canonical;
  (void)sp_differ::ValidateSemanticResult(std::string(), std::vector<uint8_t>(
                                                              semantic_bytes,
                                                              semantic_bytes + semantic_size),
                                          &canonical, &error);

  const std::string case_path =
      WriteTemporaryTextFile(HexEncode(semantic_bytes, semantic_size) + "\n");
  const std::string expected_path = WriteTemporaryFile(expected_bytes, expected_size);
  if (!case_path.empty()) {
    std::vector<uint8_t> derived;
    (void)sp_differ::DeriveNativeSendSemanticResult(std::string(), case_path, expected_path,
                                                    &derived, &error);
    if (!derived.empty() && !expected_path.empty()) {
      (void)sp_differ::CompareSemanticResultToExpected(std::string(), derived, expected_path,
                                                       nullptr, &error);
    }
    std::remove(case_path.c_str());
  }
  if (!expected_path.empty()) {
    std::vector<uint8_t> response(semantic_bytes, semantic_bytes + semantic_size);
    (void)sp_differ::CompareSemanticResultToExpected(std::string(), response, expected_path,
                                                     nullptr, &error);
    std::remove(expected_path.c_str());
  }

  (void)sp_differ::ValidateOutputPayload(
      std::vector<uint8_t>(output_bytes, output_bytes + output_size), &error);
  return 0;
}
