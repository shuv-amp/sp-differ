#include "../../ffi/sp_differ.h"

#include <stdlib.h>
#include <string.h>

namespace {

int read_u8(const uint8_t* buf, size_t len, size_t* off, uint8_t* out) {
    if (*off + 1 > len) {
        return -1;
    }
    *out = buf[*off];
    *off += 1;
    return 0;
}

int read_u16(const uint8_t* buf, size_t len, size_t* off, uint16_t* out) {
    if (*off + 2 > len) {
        return -1;
    }
    *out = (uint16_t)(buf[*off] | ((uint16_t)buf[*off + 1] << 8));
    *off += 2;
    return 0;
}

int read_u32(const uint8_t* buf, size_t len, size_t* off, uint32_t* out) {
    if (*off + 4 > len) {
        return -1;
    }
    *out = (uint32_t)(buf[*off] | ((uint32_t)buf[*off + 1] << 8) |
                      ((uint32_t)buf[*off + 2] << 16) | ((uint32_t)buf[*off + 3] << 24));
    *off += 4;
    return 0;
}

int read_u64(const uint8_t* buf, size_t len, size_t* off, uint64_t* out) {
    if (*off + 8 > len) {
        return -1;
    }
    *out = (uint64_t)(buf[*off] | ((uint64_t)buf[*off + 1] << 8) |
                      ((uint64_t)buf[*off + 2] << 16) | ((uint64_t)buf[*off + 3] << 24) |
                      ((uint64_t)buf[*off + 4] << 32) | ((uint64_t)buf[*off + 5] << 40) |
                      ((uint64_t)buf[*off + 6] << 48) | ((uint64_t)buf[*off + 7] << 56));
    *off += 8;
    return 0;
}

int read_bytes(const uint8_t* buf, size_t len, size_t* off, size_t count) {
    if (*off + count > len) {
        return -1;
    }
    *off += count;
    return 0;
}

int parse_case_v1(const uint8_t* buf, size_t len) {
    size_t off = 0;
    uint8_t version = 0;
    uint64_t seed = 0;
    uint32_t flags = 0;
    uint16_t input_count = 0;
    uint16_t output_count = 0;

    if (read_u8(buf, len, &off, &version) != 0) {
        return -1;
    }
    if (version != 1) {
        return -1;
    }
    if (read_u64(buf, len, &off, &seed) != 0) {
        return -1;
    }
    (void)seed;
    if (read_u32(buf, len, &off, &flags) != 0) {
        return -1;
    }
    if (read_u16(buf, len, &off, &input_count) != 0) {
        return -1;
    }
    if (read_u16(buf, len, &off, &output_count) != 0) {
        return -1;
    }
    (void)output_count;

    const int has_priv = (flags & (1u << 1)) != 0;
    const int has_pub = (flags & (1u << 2)) != 0;

    for (uint16_t i = 0; i < input_count; ++i) {
        uint8_t input_type = 0;
        uint32_t outpoint_vout = 0;
        if (read_bytes(buf, len, &off, 32) != 0) {
            return -1;
        }
        if (read_u32(buf, len, &off, &outpoint_vout) != 0) {
            return -1;
        }
        (void)outpoint_vout;
        if (read_u8(buf, len, &off, &input_type) != 0) {
            return -1;
        }
        if (input_type != 0x01 && input_type != 0x02 && input_type != 0x03) {
            return -1;
        }
        if (has_priv && read_bytes(buf, len, &off, 32) != 0) {
            return -1;
        }
        if (has_pub && read_bytes(buf, len, &off, 33) != 0) {
            return -1;
        }
    }

    if (read_bytes(buf, len, &off, 33) != 0) {
        return -1;
    }
    if (read_bytes(buf, len, &off, 33) != 0) {
        return -1;
    }

    uint16_t label_count = 0;
    if (read_u16(buf, len, &off, &label_count) != 0) {
        return -1;
    }

    if (label_count > 0) {
        size_t remaining = len - off;
        if (remaining / 4 < label_count) {
            return -1;
        }
        off += (size_t)label_count * 4;
    }

    if (off != len) {
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
    buffer[1] = (uint8_t)status;
    buffer[2] = 0;
    buffer[3] = 0;

    *output = buffer;
    *output_len = 4;
    return 0;
}

void sp_differ_worker_free(uint8_t* output) {
    free(output);
}
