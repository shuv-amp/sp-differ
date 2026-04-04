#include "../../ffi/sp_differ_semantic.h"

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#ifndef SP_DIFFER_SEMANTIC_SMOKE_ENV
#define SP_DIFFER_SEMANTIC_SMOKE_ENV SP_DIFFER_SEMANTIC_SMOKE_RESPONSE
#endif

#define SP_DIFFER_STRINGIFY_IMPL(value) #value
#define SP_DIFFER_STRINGIFY(value) SP_DIFFER_STRINGIFY_IMPL(value)

namespace {

bool ReadFile(const char* path, std::vector<uint8_t>* out) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    return false;
  }
  file.seekg(0, std::ios::end);
  std::streamsize size = file.tellg();
  if (size < 0) {
    return false;
  }
  file.seekg(0, std::ios::beg);
  out->resize(static_cast<size_t>(size));
  if (size > 0) {
    file.read(reinterpret_cast<char*>(out->data()), size);
  }
  return file.good() || file.eof();
}

}  // namespace

extern "C" uint32_t sp_differ_semantic_worker_api_version(void) {
  return SP_DIFFER_SEMANTIC_WORKER_API_VERSION;
}

extern "C" int sp_differ_semantic_worker_run(const uint8_t* input, size_t input_len,
                                             uint8_t** output, size_t* output_len) {
  (void)input;
  (void)input_len;

  if (output == nullptr || output_len == nullptr) {
    return 1;
  }

  const char* response_path = std::getenv(SP_DIFFER_STRINGIFY(SP_DIFFER_SEMANTIC_SMOKE_ENV));
  if (response_path == nullptr || response_path[0] == '\0') {
    return 1;
  }

  std::vector<uint8_t> response;
  if (!ReadFile(response_path, &response)) {
    return 1;
  }

  uint8_t* buffer =
      static_cast<uint8_t*>(std::malloc(response.empty() ? 1 : response.size()));
  if (buffer == nullptr) {
    return 1;
  }
  if (!response.empty()) {
    std::memcpy(buffer, response.data(), response.size());
  }

  *output = buffer;
  *output_len = response.size();
  return 0;
}

extern "C" void sp_differ_semantic_worker_free(uint8_t* output) {
  std::free(output);
}
