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

    std::cout << "OK: case parser" << std::endl;
    return 0;
}
