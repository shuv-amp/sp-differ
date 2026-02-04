#include "worker.h"

#include <string>
#include <vector>

namespace sp_differ {

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

std::string ResolveWorkerPath(const std::string& arg) {
  if (arg == "cpp") {
    return DefaultCppWorkerPath();
  }
  if (arg == "rust") {
    return DefaultRustWorkerPath();
  }
  return arg;
}

bool LoadWorker(const std::string& path, WorkerApi* api, std::string* error) {
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

void UnloadWorker(WorkerApi* api) {
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

bool RunWorker(const WorkerApi& api, const std::vector<uint8_t>& input,
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

  output->assign(output_ptr, output_ptr + output_len);
  api.free(output_ptr);
  return true;
}

}  // namespace sp_differ
