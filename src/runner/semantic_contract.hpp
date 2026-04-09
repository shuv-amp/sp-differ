#ifndef SP_DIFFER_RUNNER_SEMANTIC_CONTRACT_HPP
#define SP_DIFFER_RUNNER_SEMANTIC_CONTRACT_HPP

#include "semantic_json.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace sp_differ {

inline constexpr int64_t kSemanticContractVersion = 1;

JsonValue ValidateSemanticResultValue(const JsonValue& raw_value);
std::vector<std::string> CompareSemanticResults(const JsonValue& expected_value,
                                                const JsonValue& actual_value);
std::string JoinErrors(const std::vector<std::string>& errors);

}  // namespace sp_differ

#endif  // SP_DIFFER_RUNNER_SEMANTIC_CONTRACT_HPP
