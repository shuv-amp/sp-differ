#include "../../ffi/sp_differ.h"
#include "../../src/core/case.h"

#include <stdlib.h>

namespace {

int parse_case_v1(const uint8_t* input, size_t input_len) {
    if (!input || input_len == 0) {
        return -1;
    }

    std::vector<uint8_t> payload(input, input + input_len);
    sp_differ::Case parsed;
    std::string error;
    if (!sp_differ::ParseCaseV1(payload, &parsed, &error)) {
        return -1;
    }
    return 0;
}

}  // namespace

uint32_t sp_differ_worker_api_version(void) {
    return SP_DIFFER_WORKER_API_VERSION;
}

int sp_differ_worker_run(const uint8_t* input, size_t input_len, uint8_t** output,
                         size_t* output_len) {
    if (!input || !output || !output_len) {
        return -1;
    }

    sp_differ_status status = SP_DIFFER_STATUS_INVALID_INPUT;
    if (parse_case_v1(input, input_len) == 0) {
        status = SP_DIFFER_STATUS_OK;
    }

    uint8_t* buffer = (uint8_t*)malloc(4);
    if (!buffer) {
        return -1;
    }

    buffer[0] = 1;
    buffer[1] = static_cast<uint8_t>(status);
    buffer[2] = 0;
    buffer[3] = 0;

    *output = buffer;
    *output_len = 4;
    return 0;
}

void sp_differ_worker_free(uint8_t* output) {
    free(output);
}
