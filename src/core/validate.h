#ifndef SP_DIFFER_CORE_VALIDATE_H
#define SP_DIFFER_CORE_VALIDATE_H

#include <cstdint>
#include <string>
#include <vector>

namespace sp_differ {

bool ValidateCaseHeader(const std::vector<uint8_t>& payload, std::string* error);

}  // namespace sp_differ

#endif  // SP_DIFFER_CORE_VALIDATE_H
