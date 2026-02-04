#include "../../ffi/sp_differ.h"

#include <cctype>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace {

struct WorkerApi {
  uint32_t (*api_version)();
  int (*run)(const uint8_t*, size_t, uint8_t**, size_t*);
  void (*free)(uint8_t*);
#if defined(_WIN32)
  HMODULE handle;
#else
  void* handle;
#endif
};

std::string default_worker_path() {
#if defined(_WIN32)
  return "build\\sp_differ_worker.dll";
#elif defined(__APPLE__)
  return "build/libsp_differ_worker.dylib";
#else
  return "build/libsp_differ_worker.so";
#endif
}

bool read_file(const std::string& path, std::vector<uint8_t>* out) {
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
  return file.good();
}

bool looks_like_hex(const std::vector<uint8_t>& buf) {
  for (uint8_t byte : buf) {
    if (std::isspace(byte)) {
      continue;
    }
    if (!std::isxdigit(byte)) {
      return false;
    }
  }
  return !buf.empty();
}

int hex_value(uint8_t byte) {
  if (byte >= '0' && byte <= '9') {
    return byte - '0';
  }
  if (byte >= 'a' && byte <= 'f') {
    return 10 + (byte - 'a');
  }
  if (byte >= 'A' && byte <= 'F') {
    return 10 + (byte - 'A');
  }
  return -1;
}

bool decode_hex(const std::vector<uint8_t>& input, std::vector<uint8_t>* out) {
  std::vector<uint8_t> cleaned;
  cleaned.reserve(input.size());
  for (uint8_t byte : input) {
    if (std::isspace(byte)) {
      continue;
    }
    cleaned.push_back(byte);
  }
  if (cleaned.size() % 2 != 0) {
    return false;
  }
  out->clear();
  out->reserve(cleaned.size() / 2);
  for (size_t i = 0; i < cleaned.size(); i += 2) {
    int hi = hex_value(cleaned[i]);
    int lo = hex_value(cleaned[i + 1]);
    if (hi < 0 || lo < 0) {
      return false;
    }
    out->push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return true;
}

bool load_worker(const std::string& path, WorkerApi* api, std::string* error) {
#if defined(_WIN32)
  HMODULE handle = LoadLibraryA(path.c_str());
  if (!handle) {
    *error = "failed to load worker library";
    return false;
  }
  api->api_version = reinterpret_cast<uint32_t (*)()>(GetProcAddress(handle, "sp_differ_worker_api_version"));
  api->run = reinterpret_cast<int (*)(const uint8_t*, size_t, uint8_t**, size_t*)>(
      GetProcAddress(handle, "sp_differ_worker_run"));
  api->free = reinterpret_cast<void (*)(uint8_t*)>(GetProcAddress(handle, "sp_differ_worker_free"));
  api->handle = handle;
#else
  void* handle = dlopen(path.c_str(), RTLD_LAZY);
  if (!handle) {
    *error = "failed to load worker library";
    return false;
  }
  api->api_version = reinterpret_cast<uint32_t (*)()>(dlsym(handle, "sp_differ_worker_api_version"));
  api->run = reinterpret_cast<int (*)(const uint8_t*, size_t, uint8_t**, size_t*)>(
      dlsym(handle, "sp_differ_worker_run"));
  api->free = reinterpret_cast<void (*)(uint8_t*)>(dlsym(handle, "sp_differ_worker_free"));
  api->handle = handle;
#endif
  if (!api->api_version || !api->run || !api->free) {
    *error = "worker is missing required symbols";
    return false;
  }
  return true;
}

void unload_worker(WorkerApi* api) {
#if defined(_WIN32)
  if (api->handle) {
    FreeLibrary(api->handle);
  }
#else
  if (api->handle) {
    dlclose(api->handle);
  }
#endif
}

bool validate_output(const std::vector<uint8_t>& output, std::string* error) {
  if (output.size() < 4) {
    *error = "output too short";
    return false;
  }
  uint8_t version = output[0];
  uint8_t status = output[1];
  uint16_t output_count = static_cast<uint16_t>(output[2]) | (static_cast<uint16_t>(output[3]) << 8);

  if (version != 1) {
    *error = "unsupported output version";
    return false;
  }

  if (status != 0) {
    if (output.size() != 4) {
      *error = "non-ok status must have empty payload";
      return false;
    }
    return true;
  }

  size_t expected = 4 + static_cast<size_t>(output_count) * (33 + 32);
  if (output.size() != expected) {
    *error = "invalid payload length";
    return false;
  }
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  std::string case_path;
  std::string worker_path = default_worker_path();

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--worker") {
      if (i + 1 >= argc) {
        std::cerr << "FAIL: --worker requires a path" << std::endl;
        return 2;
      }
      worker_path = argv[++i];
    } else if (arg == "--help" || arg == "-h") {
      std::cout << "usage: sp_differ_runner <case> [--worker <path>]" << std::endl;
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

  std::vector<uint8_t> raw;
  if (!read_file(case_path, &raw)) {
    std::cerr << "FAIL: unable to read case file" << std::endl;
    return 2;
  }

  std::vector<uint8_t> input;
  if (looks_like_hex(raw)) {
    if (!decode_hex(raw, &input)) {
      std::cerr << "FAIL: invalid hex encoding" << std::endl;
      return 2;
    }
  } else {
    input = std::move(raw);
  }

  WorkerApi api{};
  std::string error;
  if (!load_worker(worker_path, &api, &error)) {
    std::cerr << "FAIL: " << error << std::endl;
    return 2;
  }

  if (api.api_version() != SP_DIFFER_WORKER_API_VERSION) {
    unload_worker(&api);
    std::cerr << "FAIL: worker ABI version mismatch" << std::endl;
    return 2;
  }

  uint8_t* output_ptr = nullptr;
  size_t output_len = 0;
  int rc = api.run(input.data(), input.size(), &output_ptr, &output_len);
  if (rc != 0) {
    unload_worker(&api);
    std::cerr << "FAIL: worker run failed" << std::endl;
    return 2;
  }

  std::vector<uint8_t> output(output_ptr, output_ptr + output_len);
  api.free(output_ptr);
  unload_worker(&api);

  if (!validate_output(output, &error)) {
    std::cerr << "FAIL: " << error << std::endl;
    return 2;
  }

  std::cout << "OK: output valid" << std::endl;
  return 0;
}
