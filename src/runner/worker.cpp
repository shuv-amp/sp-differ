// SPDX-License-Identifier: MIT
#include "worker.h"

#include "../../ffi/sp_differ_semantic.h"

#include <mutex>
#include <string>
#include <vector>

namespace sp_differ {

namespace {

std::mutex& SharedLibraryMutex() {
  static std::mutex mutex;
  return mutex;
}

template <typename ApiType>
void ResetApi(ApiType* api) {
  api->api_version = nullptr;
  api->run = nullptr;
  api->free = nullptr;
  api->handle = nullptr;
}

template <typename HandleType>
bool LoadSymbols(HandleType handle, const char* version_symbol, const char* run_symbol,
                 const char* free_symbol, WorkerApi* api) {
#if defined(_WIN32)
  api->api_version = reinterpret_cast<uint32_t (*)()>(GetProcAddress(handle, version_symbol));
  api->run = reinterpret_cast<int (*)(const uint8_t*, size_t, uint8_t**, size_t*)>(
      GetProcAddress(handle, run_symbol));
  api->free = reinterpret_cast<void (*)(uint8_t*)>(GetProcAddress(handle, free_symbol));
#else
  api->api_version = reinterpret_cast<uint32_t (*)()>(dlsym(handle, version_symbol));
  api->run = reinterpret_cast<int (*)(const uint8_t*, size_t, uint8_t**, size_t*)>(
      dlsym(handle, run_symbol));
  api->free = reinterpret_cast<void (*)(uint8_t*)>(dlsym(handle, free_symbol));
#endif
  api->handle = handle;
  return api->api_version && api->run && api->free;
}

template <typename HandleType>
bool LoadSymbols(HandleType handle, const char* version_symbol, const char* run_symbol,
                 const char* free_symbol, SemanticWorkerApi* api) {
#if defined(_WIN32)
  api->api_version = reinterpret_cast<uint32_t (*)()>(GetProcAddress(handle, version_symbol));
  api->run = reinterpret_cast<int (*)(const uint8_t*, size_t, uint8_t**, size_t*)>(
      GetProcAddress(handle, run_symbol));
  api->free = reinterpret_cast<void (*)(uint8_t*)>(GetProcAddress(handle, free_symbol));
#else
  api->api_version = reinterpret_cast<uint32_t (*)()>(dlsym(handle, version_symbol));
  api->run = reinterpret_cast<int (*)(const uint8_t*, size_t, uint8_t**, size_t*)>(
      dlsym(handle, run_symbol));
  api->free = reinterpret_cast<void (*)(uint8_t*)>(dlsym(handle, free_symbol));
#endif
  api->handle = handle;
  return api->api_version && api->run && api->free;
}

template <typename ApiType>
bool LoadSharedLibrary(const std::string& path, const char* version_symbol,
                       const char* run_symbol, const char* free_symbol, ApiType* api,
                       std::string* error) {
  std::lock_guard<std::mutex> lock(SharedLibraryMutex());
  ResetApi(api);
#if defined(_WIN32)
  HMODULE handle = LoadLibraryA(path.c_str());
  if (!handle) {
    if (error) {
      *error = "failed to load worker library: " + path;
    }
    return false;
  }
#else
  void* handle = dlopen(path.c_str(), RTLD_LAZY);
  if (!handle) {
    if (error) {
      const char* dl_error = dlerror();
      *error = dl_error ? std::string("failed to load worker library: ") + dl_error
                        : "failed to load worker library: " + path;
    }
    return false;
  }
#endif

  if (!LoadSymbols(handle, version_symbol, run_symbol, free_symbol, api)) {
    if (error) {
      *error = "worker is missing required symbols";
    }
#if defined(_WIN32)
    FreeLibrary(handle);
#else
    dlclose(handle);
#endif
    ResetApi(api);
    return false;
  }
  return true;
}

template <typename ApiType>
void UnloadSharedLibrary(ApiType* api) {
  std::lock_guard<std::mutex> lock(SharedLibraryMutex());
#if defined(_WIN32)
  if (api->handle) {
    FreeLibrary(api->handle);
  }
#else
  if (api->handle) {
    dlclose(api->handle);
  }
#endif
  ResetApi(api);
}

template <typename ApiType>
bool RunSharedWorker(const ApiType& api, const std::vector<uint8_t>& input,
                     std::vector<uint8_t>* output, std::string* error) {
  uint8_t* output_ptr = nullptr;
  size_t output_len = 0;
  int rc = api.run(input.data(), input.size(), &output_ptr, &output_len);
  if (rc != 0) {
    if (error) {
      *error = "worker run failed";
    }
    return false;
  }
  if (!output_ptr) {
    if (error) {
      *error = "worker returned no output buffer";
    }
    return false;
  }

  output->assign(output_ptr, output_ptr + output_len);
  api.free(output_ptr);
  return true;
}

}  // namespace

std::string DefaultCppWorkerPath() {
#if defined(_WIN32)
  return "build\\sp_differ_worker.dll";
#elif defined(__APPLE__)
  return "build/libsp_differ_worker.dylib";
#else
  return "build/libsp_differ_worker.so";
#endif
}

std::string DefaultRustWorkerPath() {
#if defined(_WIN32)
  return "build\\sp_differ_worker_rust.dll";
#elif defined(__APPLE__)
  return "build/libsp_differ_worker_rust.dylib";
#else
  return "build/libsp_differ_worker_rust.so";
#endif
}

std::string DefaultSpdkSemanticWorkerPath() {
#if defined(_WIN32)
  return "adapters\\spdk_rust\\target\\debug\\sp_differ_semantic_worker_spdk.dll";
#elif defined(__APPLE__)
  return "adapters/spdk_rust/target/debug/libsp_differ_semantic_worker_spdk.dylib";
#else
  return "adapters/spdk_rust/target/debug/libsp_differ_semantic_worker_spdk.so";
#endif
}

std::string DefaultSilentPaymentsSemanticWorkerPath() {
#if defined(_WIN32)
  return "adapters\\silent_payments_rust\\target\\debug\\sp_differ_semantic_worker_silent_payments.dll";
#elif defined(__APPLE__)
  return "adapters/silent_payments_rust/target/debug/libsp_differ_semantic_worker_silent_payments.dylib";
#else
  return "adapters/silent_payments_rust/target/debug/libsp_differ_semantic_worker_silent_payments.so";
#endif
}

std::string DefaultBip352SemanticWorkerPath() {
#if defined(_WIN32)
  return "adapters\\bip352_rust\\target\\debug\\sp_differ_semantic_worker_bip352.dll";
#elif defined(__APPLE__)
  return "adapters/bip352_rust/target/debug/libsp_differ_semantic_worker_bip352.dylib";
#else
  return "adapters/bip352_rust/target/debug/libsp_differ_semantic_worker_bip352.so";
#endif
}

std::string DefaultGoBip352SemanticWorkerPath() {
#if defined(_WIN32)
  return "build\\sp_differ_semantic_worker_go_bip352.dll";
#elif defined(__APPLE__)
  return "build/libsp_differ_semantic_worker_go_bip352.dylib";
#else
  return "build/libsp_differ_semantic_worker_go_bip352.so";
#endif
}

std::string ResolveWorkerPath(const std::string& arg) {
  if (arg == "cpp") {
    return DefaultCppWorkerPath();
  }
  if (arg == "rust") {
    return DefaultRustWorkerPath();
  }
  return arg;
}

std::string ResolveSemanticWorkerPath(const std::string& arg) {
  if (arg == "spdk") {
    return DefaultSpdkSemanticWorkerPath();
  }
  if (arg == "silent-payments") {
    return DefaultSilentPaymentsSemanticWorkerPath();
  }
  if (arg == "bip352") {
    return DefaultBip352SemanticWorkerPath();
  }
  if (arg == "go-bip352") {
    return DefaultGoBip352SemanticWorkerPath();
  }
  return arg;
}

bool LoadWorker(const std::string& path, WorkerApi* api, std::string* error) {
  return LoadSharedLibrary(path, "sp_differ_worker_api_version", "sp_differ_worker_run",
                           "sp_differ_worker_free", api, error);
}

void UnloadWorker(WorkerApi* api) {
  UnloadSharedLibrary(api);
}

bool LoadSemanticWorker(const std::string& path, SemanticWorkerApi* api,
                        std::string* error) {
  return LoadSharedLibrary(path, "sp_differ_semantic_worker_api_version",
                           "sp_differ_semantic_worker_run",
                           "sp_differ_semantic_worker_free", api, error);
}

void UnloadSemanticWorker(SemanticWorkerApi* api) {
  UnloadSharedLibrary(api);
}

bool RunWorker(const WorkerApi& api, const std::vector<uint8_t>& input,
               std::vector<uint8_t>* output, std::string* error) {
  return RunSharedWorker(api, input, output, error);
}

bool RunSemanticWorker(const SemanticWorkerApi& api, const std::vector<uint8_t>& input,
                       std::vector<uint8_t>* output, std::string* error) {
  return RunSharedWorker(api, input, output, error);
}

}  // namespace sp_differ
