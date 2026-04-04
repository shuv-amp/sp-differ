// SPDX-License-Identifier: MIT
#include "validate.h"
#include "io.h"

#include <iostream>

int main() {
    std::string error;
    std::vector<uint8_t> payload;
    std::vector<uint8_t> payload_v2;

    if (!sp_differ::ReadCasePayload("tests/vectors/example.hex", &payload, &error)) {
        std::cerr << "FAIL: " << error << std::endl;
        return 2;
    }
    if (!sp_differ::ReadCasePayload("tests/vectors/example_v2.hex", &payload_v2, &error)) {
        std::cerr << "FAIL: " << error << std::endl;
        return 2;
    }

    if (!sp_differ::ValidateCaseHeader(payload, &error)) {
        std::cerr << "FAIL: " << error << std::endl;
        return 2;
    }
    if (!sp_differ::ValidateCaseHeader(payload_v2, &error)) {
        std::cerr << "FAIL: " << error << std::endl;
        return 2;
    }

    std::vector<uint8_t> short_payload(payload.begin(), payload.begin() + 16);
    if (sp_differ::ValidateCaseHeader(short_payload, &error)) {
        std::cerr << "FAIL: short payload should not validate" << std::endl;
        return 2;
    }

    std::vector<uint8_t> bad_flags = payload;
    bad_flags[9] |= 0x08;
    if (sp_differ::ValidateCaseHeader(bad_flags, &error)) {
        std::cerr << "FAIL: unsupported flags should not validate" << std::endl;
        return 2;
    }

    std::vector<uint8_t> bad_flags_v2 = payload_v2;
    bad_flags_v2[10] |= 0x02;
    if (sp_differ::ValidateCaseHeader(bad_flags_v2, &error)) {
        std::cerr << "FAIL: unsupported v2 flags should not validate" << std::endl;
        return 2;
    }

    std::cout << "OK: header validation" << std::endl;
    return 0;
}
