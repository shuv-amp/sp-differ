#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <random>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

namespace {

struct Options {
  uint64_t iterations = 10000;
  uint64_t seed = 352;
  size_t max_size = 4096;
};

bool ParseOptions(int argc, char** argv, Options* out) {
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--iterations" && i + 1 < argc) {
      out->iterations = std::strtoull(argv[++i], nullptr, 10);
    } else if (arg == "--seed" && i + 1 < argc) {
      out->seed = std::strtoull(argv[++i], nullptr, 10);
    } else if (arg == "--max-size" && i + 1 < argc) {
      out->max_size = static_cast<size_t>(std::strtoull(argv[++i], nullptr, 10));
    } else if (arg == "--help" || arg == "-h") {
      return false;
    } else {
      return false;
    }
  }
  return out->max_size != 0;
}

}  // namespace

int main(int argc, char** argv) {
  Options options;
  if (!ParseOptions(argc, argv, &options)) {
    std::cerr << "usage: sp_fuzz_driver [--iterations <n>] [--seed <n>] [--max-size <n>]"
              << std::endl;
    return 2;
  }

  std::mt19937_64 rng(options.seed);
  std::uniform_int_distribution<size_t> size_dist(1, options.max_size);
  std::uniform_int_distribution<int> byte_dist(0, 255);

  std::vector<uint8_t> buffer;
  for (uint64_t iteration = 0; iteration < options.iterations; ++iteration) {
    buffer.assign(size_dist(rng), 0);
    for (uint8_t& byte : buffer) {
      byte = static_cast<uint8_t>(byte_dist(rng));
    }
    (void)LLVMFuzzerTestOneInput(buffer.data(), buffer.size());
  }

  std::cout << "OK: fuzz harness driver completed " << options.iterations << " iteration(s)"
            << std::endl;
  return 0;
}
