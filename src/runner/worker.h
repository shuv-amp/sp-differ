#ifndef SP_DIFFER_RUNNER_WORKER_H
#define SP_DIFFER_RUNNER_WORKER_H

#include <cstdint>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace sp_differ {

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

std::string DefaultCppWorkerPath();
std::string DefaultRustWorkerPath();
std::string ResolveWorkerPath(const std::string& arg);

bool LoadWorker(const std::string& path, WorkerApi* api, std::string* error);
void UnloadWorker(WorkerApi* api);

bool RunWorker(const WorkerApi& api, const std::vector<uint8_t>& input,
               std::vector<uint8_t>* output, std::string* error);

}  // namespace sp_differ

#endif  // SP_DIFFER_RUNNER_WORKER_H
