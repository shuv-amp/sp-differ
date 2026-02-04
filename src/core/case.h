#ifndef SP_DIFFER_CORE_CASE_H
#define SP_DIFFER_CORE_CASE_H

#include <cstdint>
#include <string>
#include <vector>

namespace sp_differ {

struct CaseHeader {
    uint8_t version = 0;
    uint64_t seed = 0;
    uint32_t flags = 0;
    uint16_t input_count = 0;
    uint16_t output_count = 0;
};

struct InputEntry {
    std::vector<uint8_t> outpoint_txid;
    uint32_t outpoint_vout = 0;
    uint8_t input_type = 0;
    std::vector<uint8_t> privkey;
    std::vector<uint8_t> pubkey;
};

struct Case {
    CaseHeader header;
    std::vector<InputEntry> inputs;
    std::vector<uint8_t> scan_pubkey;
    std::vector<uint8_t> spend_pubkey;
    std::vector<uint32_t> labels;
};

bool ParseCaseV1(const std::vector<uint8_t>& payload, Case* out, std::string* error);

}  // namespace sp_differ

#endif  // SP_DIFFER_CORE_CASE_H
