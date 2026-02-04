#include "io.h"

#include <cctype>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

namespace sp_differ {
namespace {

bool ReadFile(const std::string& path, std::vector<uint8_t>* out) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }
    file.seekg(0, std::ios::end);
    std::streamsize size = file.tellg();
    if (size < 0) {
        return false;
    }
    file.seekg(0, std::ios::beg);
    out->resize(static_cast<size_t>(size));
    if (size > 0) {
        file.read(reinterpret_cast<char*>(out->data()), size);
    }
    return file.good();
}

bool LooksLikeHex(const std::vector<uint8_t>& buf) {
    if (buf.empty()) {
        return false;
    }
    for (uint8_t byte : buf) {
        if (std::isspace(static_cast<unsigned char>(byte))) {
            continue;
        }
        if (!std::isxdigit(static_cast<unsigned char>(byte))) {
            return false;
        }
    }
    return true;
}

int HexValue(uint8_t byte) {
    if (byte >= '0' && byte <= '9') {
        return byte - '0';
    }
    if (byte >= 'a' && byte <= 'f') {
        return 10 + (byte - 'a');
    }
    if (byte >= 'A' && byte <= 'F') {
        return 10 + (byte - 'A');
    }
    return -1;
}

bool DecodeHex(const std::vector<uint8_t>& input, std::vector<uint8_t>* out) {
    std::vector<uint8_t> cleaned;
    cleaned.reserve(input.size());
    for (uint8_t byte : input) {
        if (std::isspace(static_cast<unsigned char>(byte))) {
            continue;
        }
        cleaned.push_back(byte);
    }
    if (cleaned.size() % 2 != 0) {
        return false;
    }
    out->clear();
    out->reserve(cleaned.size() / 2);
    for (size_t i = 0; i < cleaned.size(); i += 2) {
        int hi = HexValue(cleaned[i]);
        int lo = HexValue(cleaned[i + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out->push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

}  // namespace

bool ReadCasePayload(const std::string& path, std::vector<uint8_t>* out, std::string* error) {
    std::vector<uint8_t> raw;
    if (!ReadFile(path, &raw)) {
        if (error) {
            *error = "unable to read case file";
        }
        return false;
    }

    if (LooksLikeHex(raw)) {
        if (!DecodeHex(raw, out)) {
            if (error) {
                *error = "invalid hex encoding";
            }
            return false;
        }
        return true;
    }

    *out = std::move(raw);
    return true;
}

bool ValidateOutputPayload(const std::vector<uint8_t>& output, std::string* error) {
    if (output.size() < 4) {
        if (error) {
            *error = "output too short";
        }
        return false;
    }

    uint8_t version = output[0];
    uint8_t status = output[1];
    uint16_t output_count = static_cast<uint16_t>(output[2]) |
                            (static_cast<uint16_t>(output[3]) << 8);

    if (version != 1) {
        if (error) {
            *error = "unsupported output version";
        }
        return false;
    }

    if (status != 0) {
        if (output.size() != 4) {
            if (error) {
                *error = "non-ok status must have empty payload";
            }
            return false;
        }
        return true;
    }

    size_t expected = 4 + static_cast<size_t>(output_count) * (33 + 32);
    if (output.size() != expected) {
        if (error) {
            *error = "invalid payload length";
        }
        return false;
    }

    return true;
}

}  // namespace sp_differ
