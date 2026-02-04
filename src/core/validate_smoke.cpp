#include "validate.h"
#include "io.h"

#include <iostream>

int main() {
    std::string error;
    std::vector<uint8_t> payload;

    if (!sp_differ::ReadCasePayload("tests/vectors/example.hex", &payload, &error)) {
        std::cerr << "FAIL: " << error << std::endl;
        return 2;
    }

    if (!sp_differ::ValidateCaseHeader(payload, &error)) {
        std::cerr << "FAIL: " << error << std::endl;
        return 2;
    }

    std::cout << "OK: header validation" << std::endl;
    return 0;
}
