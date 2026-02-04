#include "case.h"

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

bool ReadBytes(const std::vector<uint8_t>& buf, size_t* off, size_t count, std::vector<uint8_t>* out) {
    if (*off + count > buf.size()) {
        return false;
    }
    out->assign(buf.begin() + static_cast<long>(*off), buf.begin() + static_cast<long>(*off + count));
    *off += count;
    return true;
}

bool IsValidInputType(uint8_t input_type) {
    return input_type == 0x01 || input_type == 0x02 || input_type == 0x03;
}

}  // namespace

bool ParseCaseV1(const std::vector<uint8_t>& payload, Case* out, std::string* error) {
    if (!out) {
        if (error) {
            *error = "output case is null";
        }
        return false;
    }

    size_t off = 0;
    CaseHeader header;
    if (!ReadU8(payload, &off, &header.version)) {
        if (error) {
            *error = "unexpected end of data";
        }
        return false;
    }
    if (header.version != 1) {
        if (error) {
            *error = "unsupported version";
        }
        return false;
    }
    if (!ReadU64(payload, &off, &header.seed) ||
        !ReadU32(payload, &off, &header.flags) ||
        !ReadU16(payload, &off, &header.input_count) ||
        !ReadU16(payload, &off, &header.output_count)) {
        if (error) {
            *error = "unexpected end of data";
        }
        return false;
    }

    Case parsed;
    parsed.header = header;

    bool has_priv = (header.flags & (1u << 1)) != 0;
    bool has_pub = (header.flags & (1u << 2)) != 0;

    parsed.inputs.reserve(header.input_count);
    for (uint16_t i = 0; i < header.input_count; ++i) {
        InputEntry entry;
        if (!ReadBytes(payload, &off, 32, &entry.outpoint_txid) ||
            !ReadU32(payload, &off, &entry.outpoint_vout) ||
            !ReadU8(payload, &off, &entry.input_type)) {
            if (error) {
                *error = "unexpected end of data";
            }
            return false;
        }
        if (!IsValidInputType(entry.input_type)) {
            if (error) {
                *error = "unknown input type";
            }
            return false;
        }
        if (has_priv && !ReadBytes(payload, &off, 32, &entry.privkey)) {
            if (error) {
                *error = "unexpected end of data";
            }
            return false;
        }
        if (has_pub && !ReadBytes(payload, &off, 33, &entry.pubkey)) {
            if (error) {
                *error = "unexpected end of data";
            }
            return false;
        }
        parsed.inputs.push_back(entry);
    }

    if (!ReadBytes(payload, &off, 33, &parsed.scan_pubkey) ||
        !ReadBytes(payload, &off, 33, &parsed.spend_pubkey)) {
        if (error) {
            *error = "unexpected end of data";
        }
        return false;
    }

    uint16_t label_count = 0;
    if (!ReadU16(payload, &off, &label_count)) {
        if (error) {
            *error = "unexpected end of data";
        }
        return false;
    }

    parsed.labels.reserve(label_count);
    for (uint16_t i = 0; i < label_count; ++i) {
        uint32_t label = 0;
        if (!ReadU32(payload, &off, &label)) {
            if (error) {
                *error = "unexpected end of data";
            }
            return false;
        }
        parsed.labels.push_back(label);
    }

    if (off != payload.size()) {
        if (error) {
            *error = "trailing bytes";
        }
        return false;
    }

    *out = std::move(parsed);
    return true;
}

}  // namespace sp_differ
