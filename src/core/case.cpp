// SPDX-License-Identifier: MIT
#include "case.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace sp_differ {
namespace {

constexpr uint32_t kSupportedCaseFlagsMaskV1 = (1u << 0) | (1u << 1) | (1u << 2);
constexpr uint32_t kSupportedCaseFlagsMaskV2 = (1u << 0) | (1u << 1) | (1u << 2) |
                                               (1u << 3) | (1u << 4) | (1u << 5) |
                                               (1u << 6) | (1u << 7) | (1u << 8);

constexpr uint32_t kFlagInputPrivateKeys = (1u << 1);
constexpr uint32_t kFlagInputPublicKeys = (1u << 2);
constexpr uint32_t kFlagPrevoutScriptPubkeys = (1u << 3);
constexpr uint32_t kFlagScriptSigs = (1u << 4);
constexpr uint32_t kFlagTxinWitnesses = (1u << 5);
constexpr uint32_t kFlagRecipientGroups = (1u << 6);
constexpr uint32_t kFlagOutputsToScan = (1u << 7);
constexpr uint32_t kFlagReceiverKeyMaterial = (1u << 8);

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

bool ReadVarBytes(const std::vector<uint8_t>& buf, size_t* off, std::vector<uint8_t>* out) {
    uint16_t count = 0;
    if (!ReadU16(buf, off, &count)) {
        return false;
    }
    return ReadBytes(buf, off, count, out);
}

// The v1 byte-worker format only models the three input types implemented by
// the byte workers. v2 adds P2PKH for the semantic path.
bool IsValidInputTypeV1(uint8_t input_type) {
    return input_type == 0x01 || input_type == 0x02 || input_type == 0x03;
}

bool IsValidInputTypeV2(uint8_t input_type) {
    return IsValidInputTypeV1(input_type) || input_type == 0x04;
}

bool HasOnlySupportedFlagsV1(uint32_t flags) {
    return (flags & ~kSupportedCaseFlagsMaskV1) == 0;
}

bool HasOnlySupportedFlagsV2(uint32_t flags) {
    return (flags & ~kSupportedCaseFlagsMaskV2) == 0;
}

bool LooksLikeCompressedPubkey(const std::vector<uint8_t>& pubkey) {
    return pubkey.size() == 33 && (pubkey[0] == 0x02 || pubkey[0] == 0x03);
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
    if (!HasOnlySupportedFlagsV1(header.flags)) {
        if (error) {
            *error = "unsupported flags";
        }
        return false;
    }

    Case parsed;
    parsed.header = header;

    bool has_priv = (header.flags & kFlagInputPrivateKeys) != 0;
    bool has_pub = (header.flags & kFlagInputPublicKeys) != 0;

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
        if (!IsValidInputTypeV1(entry.input_type)) {
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
        if (has_pub && !LooksLikeCompressedPubkey(entry.pubkey)) {
            if (error) {
                *error = "invalid public key encoding";
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
    if (!LooksLikeCompressedPubkey(parsed.scan_pubkey) ||
        !LooksLikeCompressedPubkey(parsed.spend_pubkey)) {
        if (error) {
            *error = "invalid receiver public key encoding";
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

bool ParseCaseV2(const std::vector<uint8_t>& payload, CaseV2* out, std::string* error) {
    if (!out) {
        if (error) {
            *error = "output case is null";
        }
        return false;
    }

    size_t off = 0;
    CaseHeaderV2 header;
    if (!ReadU8(payload, &off, &header.version)) {
        if (error) {
            *error = "unexpected end of data";
        }
        return false;
    }
    if (header.version != 2) {
        if (error) {
            *error = "unsupported version";
        }
        return false;
    }
    if (!ReadU64(payload, &off, &header.seed) ||
        !ReadU32(payload, &off, &header.flags) ||
        !ReadU16(payload, &off, &header.input_count) ||
        !ReadU16(payload, &off, &header.recipient_group_count) ||
        !ReadU16(payload, &off, &header.scan_output_count) ||
        !ReadU16(payload, &off, &header.label_count)) {
        if (error) {
            *error = "unexpected end of data";
        }
        return false;
    }
    if (!HasOnlySupportedFlagsV2(header.flags)) {
        if (error) {
            *error = "unsupported flags";
        }
        return false;
    }

    bool has_prevout_script_pubkeys = (header.flags & kFlagPrevoutScriptPubkeys) != 0;
    bool has_script_sigs = (header.flags & kFlagScriptSigs) != 0;
    bool has_txinwitnesses = (header.flags & kFlagTxinWitnesses) != 0;
    bool has_private_keys = (header.flags & kFlagInputPrivateKeys) != 0;
    bool has_public_keys = (header.flags & kFlagInputPublicKeys) != 0;
    bool has_recipient_groups = (header.flags & kFlagRecipientGroups) != 0;
    bool has_outputs_to_scan = (header.flags & kFlagOutputsToScan) != 0;
    bool has_receiver_key_material = (header.flags & kFlagReceiverKeyMaterial) != 0;

    // If an optional section flag is clear, its count must also be zero so
    // parsers cannot disagree about whether trailing bytes belong to that section.
    if (!has_recipient_groups && header.recipient_group_count != 0) {
        if (error) {
            *error = "unexpected recipient group count";
        }
        return false;
    }
    if (!has_outputs_to_scan && header.scan_output_count != 0) {
        if (error) {
            *error = "unexpected scan output count";
        }
        return false;
    }
    if (!has_receiver_key_material && header.label_count != 0) {
        if (error) {
            *error = "unexpected label count";
        }
        return false;
    }

    CaseV2 parsed;
    parsed.header = header;
    parsed.inputs.reserve(header.input_count);
    for (uint16_t i = 0; i < header.input_count; ++i) {
        InputEntryV2 entry;
        if (!ReadBytes(payload, &off, 32, &entry.outpoint_txid) ||
            !ReadU32(payload, &off, &entry.outpoint_vout) ||
            !ReadU8(payload, &off, &entry.input_type)) {
            if (error) {
                *error = "unexpected end of data";
            }
            return false;
        }
        if (!IsValidInputTypeV2(entry.input_type)) {
            if (error) {
                *error = "unknown input type";
            }
            return false;
        }
        if (has_prevout_script_pubkeys && !ReadVarBytes(payload, &off, &entry.prevout_script_pubkey)) {
            if (error) {
                *error = "unexpected end of data";
            }
            return false;
        }
        if (has_script_sigs && !ReadVarBytes(payload, &off, &entry.script_sig)) {
            if (error) {
                *error = "unexpected end of data";
            }
            return false;
        }
        if (has_txinwitnesses && !ReadVarBytes(payload, &off, &entry.txinwitness)) {
            if (error) {
                *error = "unexpected end of data";
            }
            return false;
        }
        if (has_private_keys && !ReadBytes(payload, &off, 32, &entry.privkey)) {
            if (error) {
                *error = "unexpected end of data";
            }
            return false;
        }
        if (has_public_keys && !ReadBytes(payload, &off, 33, &entry.pubkey)) {
            if (error) {
                *error = "unexpected end of data";
            }
            return false;
        }
        if (has_public_keys && !LooksLikeCompressedPubkey(entry.pubkey)) {
            if (error) {
                *error = "invalid public key encoding";
            }
            return false;
        }
        parsed.inputs.push_back(entry);
    }

    // v2 can carry send-side recipient groups, receive-side outputs to scan, and
    // optional receiver key material in one envelope. The flags decide which
    // sections are present for this case.
    if (has_recipient_groups) {
        parsed.recipient_groups.reserve(header.recipient_group_count);
        for (uint16_t i = 0; i < header.recipient_group_count; ++i) {
            RecipientGroupV2 group;
            if (!ReadBytes(payload, &off, 33, &group.scan_pubkey) ||
                !ReadBytes(payload, &off, 33, &group.spend_pubkey) ||
                !ReadU16(payload, &off, &group.count)) {
                if (error) {
                    *error = "unexpected end of data";
                }
                return false;
            }
            if (!LooksLikeCompressedPubkey(group.scan_pubkey) ||
                !LooksLikeCompressedPubkey(group.spend_pubkey)) {
                if (error) {
                    *error = "invalid recipient public key encoding";
                }
                return false;
            }
            if (group.count == 0) {
                if (error) {
                    *error = "recipient count must be nonzero";
                }
                return false;
            }
            parsed.recipient_groups.push_back(group);
        }
    }

    if (has_outputs_to_scan) {
        parsed.outputs_to_scan.reserve(header.scan_output_count);
        for (uint16_t i = 0; i < header.scan_output_count; ++i) {
            std::vector<uint8_t> output_key;
            if (!ReadBytes(payload, &off, 32, &output_key)) {
                if (error) {
                    *error = "unexpected end of data";
                }
                return false;
            }
            parsed.outputs_to_scan.push_back(std::move(output_key));
        }
    }

    if (has_receiver_key_material) {
        if (!ReadBytes(payload, &off, 32, &parsed.receiver_keys.scan_privkey) ||
            !ReadBytes(payload, &off, 32, &parsed.receiver_keys.spend_privkey)) {
            if (error) {
                *error = "unexpected end of data";
            }
            return false;
        }
    }

    parsed.labels.reserve(header.label_count);
    for (uint16_t i = 0; i < header.label_count; ++i) {
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
