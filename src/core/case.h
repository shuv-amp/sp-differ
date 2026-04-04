// SPDX-License-Identifier: MIT
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

struct CaseHeaderV2 {
    uint8_t version = 0;
    uint64_t seed = 0;
    uint32_t flags = 0;
    uint16_t input_count = 0;
    uint16_t recipient_group_count = 0;
    uint16_t scan_output_count = 0;
    uint16_t label_count = 0;
};

struct InputEntryV2 {
    std::vector<uint8_t> outpoint_txid;
    uint32_t outpoint_vout = 0;
    uint8_t input_type = 0;
    std::vector<uint8_t> prevout_script_pubkey;
    std::vector<uint8_t> script_sig;
    std::vector<uint8_t> txinwitness;
    std::vector<uint8_t> privkey;
    std::vector<uint8_t> pubkey;
};

struct RecipientGroupV2 {
    std::vector<uint8_t> scan_pubkey;
    std::vector<uint8_t> spend_pubkey;
    uint16_t count = 0;
};

struct ReceiverKeyMaterialV2 {
    std::vector<uint8_t> scan_privkey;
    std::vector<uint8_t> spend_privkey;
};

struct CaseV2 {
    CaseHeaderV2 header;
    std::vector<InputEntryV2> inputs;
    std::vector<RecipientGroupV2> recipient_groups;
    std::vector<std::vector<uint8_t>> outputs_to_scan;
    ReceiverKeyMaterialV2 receiver_keys;
    std::vector<uint32_t> labels;
};

bool ParseCaseV1(const std::vector<uint8_t>& payload, Case* out, std::string* error);
bool ParseCaseV2(const std::vector<uint8_t>& payload, CaseV2* out, std::string* error);

}  // namespace sp_differ

#endif  // SP_DIFFER_CORE_CASE_H
