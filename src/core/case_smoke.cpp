// SPDX-License-Identifier: MIT
#include "case.h"
#include "io.h"

#include <iostream>

int main() {
    std::string error;
    std::vector<uint8_t> payload;
    if (!sp_differ::ReadCasePayload("tests/vectors/example.hex", &payload, &error)) {
        std::cerr << "FAIL: " << error << std::endl;
        return 2;
    }

    sp_differ::Case parsed;
    if (!sp_differ::ParseCaseV1(payload, &parsed, &error)) {
        std::cerr << "FAIL: " << error << std::endl;
        return 2;
    }

    if (parsed.header.input_count != 1 || parsed.header.output_count != 1) {
        std::cerr << "FAIL: unexpected header values" << std::endl;
        return 2;
    }

    if (payload.size() > 1) {
        std::vector<uint8_t> truncated(payload.begin(), payload.end() - 1);
        sp_differ::Case should_fail;
        if (sp_differ::ParseCaseV1(truncated, &should_fail, &error)) {
            std::cerr << "FAIL: truncated payload should not parse" << std::endl;
            return 2;
        }
    }

    std::vector<uint8_t> bad_flags = payload;
    bad_flags[9] |= 0x08;
    if (sp_differ::ParseCaseV1(bad_flags, &parsed, &error)) {
        std::cerr << "FAIL: unsupported flags should not parse" << std::endl;
        return 2;
    }

    std::vector<uint8_t> bad_receiver = payload;
    size_t scan_pubkey_offset = 17 + 32 + 4 + 1 + 32;
    bad_receiver[scan_pubkey_offset] = 0x04;
    if (sp_differ::ParseCaseV1(bad_receiver, &parsed, &error)) {
        std::cerr << "FAIL: invalid receiver pubkey encoding should not parse" << std::endl;
        return 2;
    }

    std::vector<uint8_t> payload_v2;
    if (!sp_differ::ReadCasePayload("tests/vectors/example_v2.hex", &payload_v2, &error)) {
        std::cerr << "FAIL: " << error << std::endl;
        return 2;
    }

    sp_differ::CaseV2 parsed_v2;
    if (!sp_differ::ParseCaseV2(payload_v2, &parsed_v2, &error)) {
        std::cerr << "FAIL: " << error << std::endl;
        return 2;
    }

    if (parsed_v2.header.input_count != 1 ||
        parsed_v2.header.recipient_group_count != 2 ||
        parsed_v2.header.scan_output_count != 1 ||
        parsed_v2.header.label_count != 2 ||
        parsed_v2.inputs[0].input_type != 0x04 ||
        parsed_v2.outputs_to_scan.size() != 1 ||
        parsed_v2.labels.size() != 2) {
        std::cerr << "FAIL: unexpected v2 values" << std::endl;
        return 2;
    }

    if (payload_v2.size() > 1) {
        std::vector<uint8_t> truncated_v2(payload_v2.begin(), payload_v2.end() - 1);
        sp_differ::CaseV2 should_fail_v2;
        if (sp_differ::ParseCaseV2(truncated_v2, &should_fail_v2, &error)) {
            std::cerr << "FAIL: truncated v2 payload should not parse" << std::endl;
            return 2;
        }
    }

    std::vector<uint8_t> bad_flags_v2 = payload_v2;
    bad_flags_v2[10] |= 0x02;
    if (sp_differ::ParseCaseV2(bad_flags_v2, &parsed_v2, &error)) {
        std::cerr << "FAIL: unsupported v2 flags should not parse" << std::endl;
        return 2;
    }

    std::vector<uint8_t> bad_recipient = payload_v2;
    size_t recipient_scan_pubkey_offset = 21 + 32 + 4 + 1 + 2 + 25 + 2 + 107 + 2 + 32;
    bad_recipient[recipient_scan_pubkey_offset] = 0x04;
    if (sp_differ::ParseCaseV2(bad_recipient, &parsed_v2, &error)) {
        std::cerr << "FAIL: invalid v2 recipient pubkey encoding should not parse" << std::endl;
        return 2;
    }

    std::cout << "OK: case parser" << std::endl;
    return 0;
}
