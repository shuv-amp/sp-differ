// SPDX-License-Identifier: MIT
#include "io.h"

#include <iostream>

int main() {
    std::string error;
    std::vector<uint8_t> payload;
    if (!sp_differ::ReadCasePayload("tests/vectors/example.hex", &payload, &error)) {
        std::cerr << "FAIL: " << error << std::endl;
        return 2;
    }

    std::vector<uint8_t> output;
    if (!sp_differ::ReadCasePayload("tests/vectors/output_ok.hex", &output, &error)) {
        std::cerr << "FAIL: " << error << std::endl;
        return 2;
    }

    if (!sp_differ::ValidateOutputPayload(output, &error)) {
        std::cerr << "FAIL: " << error << std::endl;
        return 2;
    }

    std::vector<uint8_t> unknown_status = {1, 0x06, 0x00, 0x00};
    if (sp_differ::ValidateOutputPayload(unknown_status, &error)) {
        std::cerr << "FAIL: unknown status should not validate" << std::endl;
        return 2;
    }

    std::vector<uint8_t> non_ok_with_payload = {1, 0x01, 0x01, 0x00, 0x02};
    if (sp_differ::ValidateOutputPayload(non_ok_with_payload, &error)) {
        std::cerr << "FAIL: non-ok payload bytes should not validate" << std::endl;
        return 2;
    }

    std::cout << "OK: core io" << std::endl;
    return 0;
}
