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

    std::cout << "OK: core io" << std::endl;
    return 0;
}
