// SPDX-License-Identifier: MIT
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

struct SemanticWorkerApi {
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
std::string DefaultSpdkSemanticWorkerPath();
std::string DefaultSilentPaymentsSemanticWorkerPath();
std::string DefaultBip352SemanticWorkerPath();
std::string DefaultGoBip352SemanticWorkerPath();
std::string ResolveSemanticWorkerPath(const std::string& arg);

bool LoadWorker(const std::string& path, WorkerApi* api, std::string* error);
void UnloadWorker(WorkerApi* api);
bool LoadSemanticWorker(const std::string& path, SemanticWorkerApi* api, std::string* error);
void UnloadSemanticWorker(SemanticWorkerApi* api);

bool RunWorker(const WorkerApi& api, const std::vector<uint8_t>& input,
               std::vector<uint8_t>* output, std::string* error);
bool RunSemanticWorker(const SemanticWorkerApi& api, const std::vector<uint8_t>& input,
                       std::vector<uint8_t>* output, std::string* error);

}  // namespace sp_differ

#endif  // SP_DIFFER_RUNNER_WORKER_H
