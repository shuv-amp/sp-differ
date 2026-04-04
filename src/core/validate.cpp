// SPDX-License-Identifier: MIT
#include "validate.h"

#include <cstdint>
#include <string>
#include <vector>

namespace sp_differ {
namespace {

constexpr uint32_t kSupportedCaseFlagsMaskV1 = (1u << 0) | (1u << 1) | (1u << 2);
constexpr uint32_t kSupportedCaseFlagsMaskV2 = (1u << 0) | (1u << 1) | (1u << 2) |
                                               (1u << 3) | (1u << 4) | (1u << 5) |
                                               (1u << 6) | (1u << 7) | (1u << 8);

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

    if (!ReadU8(payload, &off, &version) ||
        !ReadU64(payload, &off, &seed) ||
        !ReadU32(payload, &off, &flags)) {
        if (error) {
            *error = "case header too short";
        }
        return false;
    }

    // This is a shallow header check: verify the fixed-size header fields and the
    // supported flag mask, then leave full structural validation to ParseCaseV1.
    (void)seed;
    if (version == 1) {
        uint16_t input_count = 0;
        uint16_t output_count = 0;
        if (!ReadU16(payload, &off, &input_count) ||
            !ReadU16(payload, &off, &output_count)) {
            if (error) {
                *error = "case header too short";
            }
            return false;
        }
        if ((flags & ~kSupportedCaseFlagsMaskV1) != 0) {
            if (error) {
                *error = "unsupported flags";
            }
            return false;
        }

        (void)input_count;
        (void)output_count;
        return true;
    }

    // Same for v2: this gate only checks that the header is present and the flag
    // set is supported before the full parser walks the optional sections.
    if (version == 2) {
        uint16_t input_count = 0;
        uint16_t recipient_group_count = 0;
        uint16_t scan_output_count = 0;
        uint16_t label_count = 0;
        if (!ReadU16(payload, &off, &input_count) ||
            !ReadU16(payload, &off, &recipient_group_count) ||
            !ReadU16(payload, &off, &scan_output_count) ||
            !ReadU16(payload, &off, &label_count)) {
            if (error) {
                *error = "case header too short";
            }
            return false;
        }
        if ((flags & ~kSupportedCaseFlagsMaskV2) != 0) {
            if (error) {
                *error = "unsupported flags";
            }
            return false;
        }

        (void)input_count;
        (void)recipient_group_count;
        (void)scan_output_count;
        (void)label_count;
        return true;
    }

    {
        if (error) {
            *error = "unsupported version";
        }
        return false;
    }
}

}  // namespace sp_differ
