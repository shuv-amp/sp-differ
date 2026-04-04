#ifndef SP_DIFFER_RUNNER_SEMANTIC_BRIDGE_HPP
#define SP_DIFFER_RUNNER_SEMANTIC_BRIDGE_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace sp_differ {

struct SemanticRequestOptions {
  std::string expectation_path;
  std::string kind = "auto";
  std::string network = "mainnet";
  uint32_t silent_payment_version = 0;
};

struct SemanticExpectationSummary {
  std::string kind;
  std::string semantic_status;
  bool detailed_outputs_available = false;
  std::vector<std::vector<std::string>> acceptable_output_sets;
  std::string source_id;
};

struct NativeSemanticOptions {
  std::string network = "mainnet";
  uint32_t silent_payment_version = 0;
};

struct NativeScanBenchmarkOptions {
  std::string network = "mainnet";
  uint32_t silent_payment_version = 0;
  uint32_t block_count = 1000;
  uint32_t transactions_per_block = 8;
  uint32_t thread_count = 0;
  uint64_t seed = 352;
  std::string density = "all";
};

struct NativeScanBenchmarkProfile {
  std::string density;
  uint32_t outputs_per_transaction = 0;
  uint64_t block_count = 0;
  uint64_t transaction_count = 0;
  uint64_t output_count = 0;
  uint64_t matched_transaction_count = 0;
  uint64_t found_output_count = 0;
  uint64_t elapsed_nanoseconds = 0;
};

struct NativeScanBenchmarkReport {
  std::string network = "mainnet";
  uint32_t silent_payment_version = 0;
  uint64_t seed = 352;
  uint32_t block_count = 1000;
  uint32_t transactions_per_block = 8;
  uint32_t thread_count = 0;
  std::vector<NativeScanBenchmarkProfile> profiles;
};

struct DescriptorWalletExport {
  std::string network = "mainnet";
  uint32_t silent_payment_version = 0;
  std::string scan_secret_key_hex;
  std::string spend_secret_key_hex;
  std::string scan_secret_key_wif;
  std::string spend_secret_key_wif;
  std::string scan_key_expression;
  std::string taproot_descriptor;
  std::string silent_payment_address;
  std::string warning;
};

std::string DetectRepoRoot(const char* argv0);
std::string DefaultExpectationPath(const std::string& case_path);

bool BuildSemanticRequest(const std::string& repo_root, const std::string& case_path,
                          const SemanticRequestOptions& options,
                          std::vector<uint8_t>* request_json, std::string* error);
uint32_t SemanticAdapterRequestVersion();
uint32_t SemanticContractVersion();
bool LoadSemanticExpectationSummary(const std::string& expected_path,
                                    SemanticExpectationSummary* summary,
                                    std::string* error);
bool DeriveNativeSemanticResult(const std::string& repo_root,
                                const std::string& case_path,
                                const std::string& expected_path,
                                const NativeSemanticOptions& options,
                                std::vector<uint8_t>* canonical_json,
                                std::string* error);
bool RunNativeScanBenchmark(const NativeScanBenchmarkOptions& options,
                            NativeScanBenchmarkReport* report, std::string* error);
bool ExportDescriptorWallet(const std::string& network,
                            uint32_t silent_payment_version,
                            const std::string& scan_secret_key_hex,
                            const std::string& spend_secret_key_hex,
                            DescriptorWalletExport* export_data, std::string* error);
bool DeriveNativeSendSemanticResult(const std::string& repo_root,
                                    const std::string& case_path,
                                    const std::string& expected_path,
                                    std::vector<uint8_t>* canonical_json,
                                    std::string* error);
bool ValidateSemanticResult(const std::string& repo_root,
                            const std::vector<uint8_t>& response_json,
                            std::vector<uint8_t>* canonical_json, std::string* error);
bool CompareSemanticResultToExpected(const std::string& repo_root,
                                     const std::vector<uint8_t>& response_json,
                                     const std::string& expected_path,
                                     std::vector<uint8_t>* canonical_json,
                                     std::string* error);

}  // namespace sp_differ

#endif  // SP_DIFFER_RUNNER_SEMANTIC_BRIDGE_HPP
