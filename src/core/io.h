#ifndef SP_DIFFER_CORE_IO_H
#define SP_DIFFER_CORE_IO_H

#include <cstdint>
#include <string>
#include <vector>

namespace sp_differ {

bool ReadCasePayload(const std::string& path, std::vector<uint8_t>* out, std::string* error);

bool ValidateOutputPayload(const std::vector<uint8_t>& output, std::string* error);

}  // namespace sp_differ

#endif  // SP_DIFFER_CORE_IO_H
