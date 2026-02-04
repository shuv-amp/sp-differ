#include "validate.h"

#include <cstdint>
#include <string>
#include <vector>

namespace sp_differ {
namespace {

bool ReadU8(const std::vector<uint8_t>& buf, size_t* off, uint8_t* out) {
    if (*off + 1 > buf.size()) {
        return false;
    }
    *out = buf[*off];
    *off += 1;
    return true;
}

bool ReadU16(const std::vector<uint8_t>& buf, size_t* off, uint16_t* out) {
    if (*off + 2 > buf.size()) {
        return false;
    }
    *out = static_cast<uint16_t>(buf[*off] | (static_cast<uint16_t>(buf[*off + 1]) << 8));
    *off += 2;
    return true;
}

bool ReadU32(const std::vector<uint8_t>& buf, size_t* off, uint32_t* out) {
    if (*off + 4 > buf.size()) {
        return false;
    }
    *out = static_cast<uint32_t>(buf[*off]) |
           (static_cast<uint32_t>(buf[*off + 1]) << 8) |
           (static_cast<uint32_t>(buf[*off + 2]) << 16) |
           (static_cast<uint32_t>(buf[*off + 3]) << 24);
    *off += 4;
    return true;
}

bool ReadU64(const std::vector<uint8_t>& buf, size_t* off, uint64_t* out) {
    if (*off + 8 > buf.size()) {
        return false;
    }
    *out = static_cast<uint64_t>(buf[*off]) |
           (static_cast<uint64_t>(buf[*off + 1]) << 8) |
           (static_cast<uint64_t>(buf[*off + 2]) << 16) |
           (static_cast<uint64_t>(buf[*off + 3]) << 24) |
           (static_cast<uint64_t>(buf[*off + 4]) << 32) |
           (static_cast<uint64_t>(buf[*off + 5]) << 40) |
           (static_cast<uint64_t>(buf[*off + 6]) << 48) |
           (static_cast<uint64_t>(buf[*off + 7]) << 56);
    *off += 8;
    return true;
}

}  // namespace

bool ValidateCaseHeader(const std::vector<uint8_t>& payload, std::string* error) {
    size_t off = 0;
    uint8_t version = 0;
    uint64_t seed = 0;
    uint32_t flags = 0;
    uint16_t input_count = 0;
    uint16_t output_count = 0;

    if (!ReadU8(payload, &off, &version) ||
        !ReadU64(payload, &off, &seed) ||
        !ReadU32(payload, &off, &flags) ||
        !ReadU16(payload, &off, &input_count) ||
        !ReadU16(payload, &off, &output_count)) {
        if (error) {
            *error = "case header too short";
        }
        return false;
    }

    (void)seed;
    if (version != 1) {
        if (error) {
            *error = "unsupported version";
        }
        return false;
    }

    (void)input_count;
    (void)output_count;

    return true;
}

}  // namespace sp_differ
