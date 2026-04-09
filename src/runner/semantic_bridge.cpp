// SPDX-License-Identifier: MIT
#include "semantic_bridge.hpp"
#include "semantic_contract.hpp"
#include "semantic_encoding.hpp"
#include "semantic_json.hpp"

#include "../core/case.h"
#include "../core/io.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

namespace sp_differ {
namespace {

constexpr uint32_t kFlagInputPrivateKeys = (1u << 1);
constexpr uint32_t kFlagInputPublicKeys = (1u << 2);
constexpr uint32_t kFlagPrevoutScriptPubkeys = (1u << 3);
constexpr uint32_t kFlagScriptSigs = (1u << 4);
constexpr uint32_t kFlagTxinWitnesses = (1u << 5);
constexpr uint32_t kFlagRecipientGroups = (1u << 6);
constexpr uint32_t kFlagReceiverKeyMaterial = (1u << 8);

constexpr int64_t kSemanticAdapterRequestVersion = 1;
constexpr uint32_t kRecipientLimit = 2323;

const std::regex kOfficialCaseRegex("^official_case_(\\d+)_(send|receive)_(\\d+)$");
const std::array<unsigned char, 32> kNumsH = {
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b,
    0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec,
    0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
};
const char* kSecp256k1OrderHex =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
struct EligibleInput {
  uint8_t input_type = 0;
  std::array<unsigned char, 33> pubkey{};
  std::string pubkey_hex;
  std::array<unsigned char, 32> privkey{};
  bool has_privkey = false;
  bool is_xonly = false;
};

struct SenderScanGroup {
  std::array<unsigned char, 33> scan_pubkey{};
  std::string scan_pubkey_hex;
  std::vector<std::array<unsigned char, 33>> spend_pubkeys;
  std::vector<std::string> spend_pubkey_hexes;
};

struct SecpContextDeleter {
  void operator()(secp256k1_context* context) const {
    if (context != nullptr) {
      secp256k1_context_destroy(context);
    }
  }
};

using SecpContextPtr = std::unique_ptr<secp256k1_context, SecpContextDeleter>;

struct ReceiveScanCoreResult {
  std::string semantic_status = "ok";
  JsonArray input_pubkeys;
  std::array<unsigned char, 33> input_pubkey_sum{};
  std::array<unsigned char, 32> input_hash{};
  std::array<unsigned char, 33> tweak{};
  std::array<unsigned char, 33> shared_secret{};
  secp256k1_pubkey spend_pubkey{};
  bool has_input_pubkey_sum = false;
  bool has_input_hash = false;
  bool has_tweak = false;
  bool has_shared_secret = false;
  bool has_spend_pubkey = false;
};

struct BenchmarkDensityProfile {
  const char* name;
  uint32_t outputs_per_transaction;
};

std::vector<uint8_t> ToBytes(const std::string& text) {
  return std::vector<uint8_t>(text.begin(), text.end());
}

bool IsKnownKind(const std::string& value) {
  return value == "send" || value == "receive";
}

bool IsKnownNetwork(const std::string& value) {
  return value == "mainnet" || value == "testnet" || value == "regtest" ||
         value == "signet";
}

int HexValue(char ch) {
  if (ch >= '0' && ch <= '9') {
    return ch - '0';
  }
  if (ch >= 'a' && ch <= 'f') {
    return 10 + (ch - 'a');
  }
  if (ch >= 'A' && ch <= 'F') {
    return 10 + (ch - 'A');
  }
  return -1;
}

bool IsHexString(const std::string& value, size_t expected_len = 0) {
  if (expected_len != 0 && value.size() != expected_len) {
    return false;
  }
  for (char ch : value) {
    if (HexValue(ch) < 0) {
      return false;
    }
  }
  return true;
}

std::string HexEncode(const std::vector<uint8_t>& bytes) {
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (uint8_t byte : bytes) {
    out.push_back(kHex[(byte >> 4) & 0x0F]);
    out.push_back(kHex[byte & 0x0F]);
  }
  return out;
}

std::string HexEncodeReversed(const std::vector<uint8_t>& bytes) {
  std::vector<uint8_t> reversed(bytes.rbegin(), bytes.rend());
  return HexEncode(reversed);
}

bool HasFlag(uint32_t flags, uint32_t mask) {
  return (flags & mask) != 0;
}

uint64_t ReadCompactSize(const std::vector<uint8_t>& bytes, size_t* offset) {
  if (*offset >= bytes.size()) {
    throw SemanticBridgeError("unexpected end of txinwitness");
  }
  const uint8_t value = bytes[*offset];
  *offset += 1;
  if (value < 253) {
    return value;
  }
  if (value == 253) {
    if (*offset + 2 > bytes.size()) {
      throw SemanticBridgeError("unexpected end of txinwitness");
    }
    const uint64_t decoded = static_cast<uint64_t>(bytes[*offset]) |
                             (static_cast<uint64_t>(bytes[*offset + 1]) << 8);
    *offset += 2;
    return decoded;
  }
  if (value == 254) {
    if (*offset + 4 > bytes.size()) {
      throw SemanticBridgeError("unexpected end of txinwitness");
    }
    uint64_t decoded = 0;
    for (size_t i = 0; i < 4; ++i) {
      decoded |= (static_cast<uint64_t>(bytes[*offset + i]) << (8 * i));
    }
    *offset += 4;
    return decoded;
  }
  if (*offset + 8 > bytes.size()) {
    throw SemanticBridgeError("unexpected end of txinwitness");
  }
  uint64_t decoded = 0;
  for (size_t i = 0; i < 8; ++i) {
    decoded |= (static_cast<uint64_t>(bytes[*offset + i]) << (8 * i));
  }
  *offset += 8;
  return decoded;
}

JsonArray DecodeTxInWitnessStack(const std::vector<uint8_t>& bytes) {
  JsonArray stack;
  if (bytes.empty()) {
    return stack;
  }
  size_t offset = 0;
  const uint64_t item_count = ReadCompactSize(bytes, &offset);
  for (uint64_t i = 0; i < item_count; ++i) {
    const uint64_t size = ReadCompactSize(bytes, &offset);
    if (offset + size > bytes.size()) {
      throw SemanticBridgeError("unexpected end of txinwitness item");
    }
    stack.emplace_back(HexEncode(std::vector<uint8_t>(bytes.begin() + static_cast<long>(offset),
                                                      bytes.begin() +
                                                          static_cast<long>(offset + size))));
    offset += static_cast<size_t>(size);
  }
  if (offset != bytes.size()) {
    throw SemanticBridgeError("trailing bytes in txinwitness");
  }
  return stack;
}

struct BnDeleter {
  void operator()(BIGNUM* value) const {
    if (value != nullptr) {
      BN_free(value);
    }
  }
};

struct BnCtxDeleter {
  void operator()(BN_CTX* value) const {
    if (value != nullptr) {
      BN_CTX_free(value);
    }
  }
};

using BnPtr = std::unique_ptr<BIGNUM, BnDeleter>;
using BnCtxPtr = std::unique_ptr<BN_CTX, BnCtxDeleter>;

SecpContextPtr CreateSecpContext() {
  SecpContextPtr context(
      secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY));
  if (!context) {
    throw SemanticBridgeError("unable to initialize secp256k1 context");
  }
  return context;
}

BnPtr LoadSecp256k1Order() {
  BIGNUM* raw = nullptr;
  if (BN_hex2bn(&raw, kSecp256k1OrderHex) == 0 || raw == nullptr) {
    throw SemanticBridgeError("unable to initialize secp256k1 order");
  }
  return BnPtr(raw);
}

bool ScalarIsZero(const std::array<unsigned char, 32>& scalar) {
  for (unsigned char byte : scalar) {
    if (byte != 0) {
      return false;
    }
  }
  return true;
}

bool VerifyScalar(const secp256k1_context* ctx, const std::array<unsigned char, 32>& scalar) {
  return secp256k1_ec_seckey_verify(ctx, scalar.data()) == 1;
}

bool SerializeCompressedPubkey(const secp256k1_context* ctx,
                               const secp256k1_pubkey& pubkey,
                               std::array<unsigned char, 33>* out) {
  size_t size = out->size();
  return secp256k1_ec_pubkey_serialize(ctx, out->data(), &size, &pubkey,
                                       SECP256K1_EC_COMPRESSED) == 1 &&
         size == out->size();
}

bool ParseCompressedPubkey(const secp256k1_context* ctx,
                           const std::array<unsigned char, 33>& encoded,
                           secp256k1_pubkey* out) {
  return secp256k1_ec_pubkey_parse(ctx, out, encoded.data(), encoded.size()) == 1;
}

bool ParseXOnlyPubkey(const secp256k1_context* ctx,
                     const std::array<unsigned char, 32>& xonly,
                     secp256k1_pubkey* out) {
  std::array<unsigned char, 33> encoded{};
  encoded[0] = 0x02;
  std::memcpy(encoded.data() + 1, xonly.data(), xonly.size());
  return ParseCompressedPubkey(ctx, encoded, out);
}

bool CreatePubkeyFromScalar(const secp256k1_context* ctx,
                            const std::array<unsigned char, 32>& scalar,
                            secp256k1_pubkey* out) {
  return secp256k1_ec_pubkey_create(ctx, out, scalar.data()) == 1;
}

bool SerializeXOnlyPubkey(const secp256k1_context* ctx, const secp256k1_pubkey& pubkey,
                          std::array<unsigned char, 32>* out) {
  secp256k1_xonly_pubkey xonly_pubkey;
  int parity = 0;
  if (secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly_pubkey, &parity, &pubkey) != 1) {
    return false;
  }
  return secp256k1_xonly_pubkey_serialize(ctx, out->data(), &xonly_pubkey) == 1;
}

std::string HexEncodeFixed(const unsigned char* data, size_t size) {
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.reserve(size * 2);
  for (size_t i = 0; i < size; ++i) {
    out.push_back(kHex[(data[i] >> 4) & 0x0F]);
    out.push_back(kHex[data[i] & 0x0F]);
  }
  return out;
}

std::array<unsigned char, 32> HexToArray32(const std::string& value) {
  if (!IsHexString(value, 64)) {
    throw SemanticBridgeError("invalid 32-byte hex string");
  }
  std::array<unsigned char, 32> out{};
  for (size_t i = 0; i < out.size(); ++i) {
    const int high = HexValue(value[i * 2]);
    const int low = HexValue(value[i * 2 + 1]);
    out[i] = static_cast<unsigned char>((high << 4) | low);
  }
  return out;
}

std::array<unsigned char, 32> BytesToArray32(const std::vector<uint8_t>& value,
                                             const char* what) {
  if (value.size() != 32) {
    throw SemanticBridgeError(std::string("invalid ") + what);
  }
  std::array<unsigned char, 32> out{};
  std::memcpy(out.data(), value.data(), out.size());
  return out;
}

bool CombinePubkeys(const secp256k1_context* ctx, const std::vector<secp256k1_pubkey>& pubkeys,
                    secp256k1_pubkey* out) {
  if (pubkeys.empty()) {
    return false;
  }
  if (pubkeys.size() == 1) {
    *out = pubkeys.front();
    return true;
  }
  std::vector<const secp256k1_pubkey*> pointers;
  pointers.reserve(pubkeys.size());
  for (const secp256k1_pubkey& pubkey : pubkeys) {
    pointers.push_back(&pubkey);
  }
  return secp256k1_ec_pubkey_combine(ctx, out, pointers.data(), pointers.size()) == 1;
}

secp256k1_pubkey NegatedPubkey(const secp256k1_context* ctx, const secp256k1_pubkey& pubkey) {
  secp256k1_pubkey negated = pubkey;
  if (secp256k1_ec_pubkey_negate(ctx, &negated) != 1) {
    throw SemanticBridgeError("unable to negate public key");
  }
  return negated;
}

secp256k1_pubkey AddPubkeys(const secp256k1_context* ctx, const secp256k1_pubkey& left,
                            const secp256k1_pubkey& right) {
  const std::vector<secp256k1_pubkey> pubkeys = {left, right};
  secp256k1_pubkey combined;
  if (!CombinePubkeys(ctx, pubkeys, &combined)) {
    throw SemanticBridgeError("unable to add public keys");
  }
  return combined;
}

secp256k1_pubkey SubtractPubkeys(const secp256k1_context* ctx, const secp256k1_pubkey& left,
                                 const secp256k1_pubkey& right) {
  return AddPubkeys(ctx, left, NegatedPubkey(ctx, right));
}

std::vector<std::vector<uint8_t>> DecodeTxInWitnessItems(const std::vector<uint8_t>& bytes) {
  std::vector<std::vector<uint8_t>> stack;
  if (bytes.empty()) {
    return stack;
  }
  size_t offset = 0;
  const uint64_t item_count = ReadCompactSize(bytes, &offset);
  stack.reserve(static_cast<size_t>(item_count));
  for (uint64_t i = 0; i < item_count; ++i) {
    const uint64_t size = ReadCompactSize(bytes, &offset);
    if (offset + size > bytes.size()) {
      throw SemanticBridgeError("unexpected end of txinwitness item");
    }
    stack.emplace_back(bytes.begin() + static_cast<long>(offset),
                       bytes.begin() + static_cast<long>(offset + size));
    offset += static_cast<size_t>(size);
  }
  if (offset != bytes.size()) {
    throw SemanticBridgeError("trailing bytes in txinwitness");
  }
  return stack;
}

bool IsCompressedPubkeyBytes(const std::vector<uint8_t>& bytes) {
  return bytes.size() == 33 && (bytes[0] == 0x02 || bytes[0] == 0x03);
}

bool IsP2TRScriptPubKey(const std::vector<uint8_t>& script) {
  return script.size() == 34 && script[0] == 0x51 && script[1] == 0x20;
}

bool IsP2WPKHScriptPubKey(const std::vector<uint8_t>& script) {
  return script.size() == 22 && script[0] == 0x00 && script[1] == 0x14;
}

bool IsP2SHScriptPubKey(const std::vector<uint8_t>& script) {
  return script.size() == 23 && script[0] == 0xA9 && script[1] == 0x14 &&
         script[22] == 0x87;
}

bool IsP2PKHScriptPubKey(const std::vector<uint8_t>& script) {
  return script.size() == 25 && script[0] == 0x76 && script[1] == 0xA9 &&
         script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xAC;
}

bool Hash160(const std::vector<uint8_t>& bytes, std::array<unsigned char, 20>* out) {
  std::array<unsigned char, SHA256_DIGEST_LENGTH> sha256{};
  if (SHA256(bytes.data(), bytes.size(), sha256.data()) == nullptr) {
    return false;
  }
  unsigned int digest_size = 0;
  return EVP_Digest(sha256.data(), sha256.size(), out->data(), &digest_size,
                    EVP_ripemd160(), nullptr) == 1 &&
         digest_size == out->size();
}

bool ExtractCompressedPubkeyFromBytes(const std::vector<uint8_t>& bytes,
                                      std::array<unsigned char, 33>* out) {
  if (!IsCompressedPubkeyBytes(bytes)) {
    return false;
  }
  std::memcpy(out->data(), bytes.data(), out->size());
  return true;
}

bool ExtractP2PKHPubkey(const InputEntryV2& entry, std::array<unsigned char, 33>* out) {
  if (!IsP2PKHScriptPubKey(entry.prevout_script_pubkey)) {
    return false;
  }
  std::array<unsigned char, 20> expected_hash{};
  std::memcpy(expected_hash.data(), entry.prevout_script_pubkey.data() + 3,
              expected_hash.size());
  for (size_t i = entry.script_sig.size(); i > 0; --i) {
    if (i < 33) {
      break;
    }
    std::vector<uint8_t> candidate(entry.script_sig.begin() + static_cast<long>(i - 33),
                                   entry.script_sig.begin() + static_cast<long>(i));
    std::array<unsigned char, 20> candidate_hash{};
    if (!ExtractCompressedPubkeyFromBytes(candidate, out) || !Hash160(candidate, &candidate_hash)) {
      continue;
    }
    if (candidate_hash == expected_hash) {
      return true;
    }
  }
  return false;
}

bool ExtractP2SHP2WPKHPubkey(const InputEntryV2& entry, std::array<unsigned char, 33>* out) {
  if (!IsP2SHScriptPubKey(entry.prevout_script_pubkey) || entry.script_sig.empty()) {
    return false;
  }
  std::vector<uint8_t> redeem_script(entry.script_sig.begin() + 1, entry.script_sig.end());
  if (!IsP2WPKHScriptPubKey(redeem_script)) {
    return false;
  }
  const std::vector<std::vector<uint8_t>> witness_stack = DecodeTxInWitnessItems(entry.txinwitness);
  if (witness_stack.empty()) {
    return false;
  }
  return ExtractCompressedPubkeyFromBytes(witness_stack.back(), out);
}

bool ExtractP2WPKHPubkey(const InputEntryV2& entry, std::array<unsigned char, 33>* out) {
  if (!IsP2WPKHScriptPubKey(entry.prevout_script_pubkey)) {
    return false;
  }
  const std::vector<std::vector<uint8_t>> witness_stack = DecodeTxInWitnessItems(entry.txinwitness);
  if (witness_stack.empty()) {
    return false;
  }
  return ExtractCompressedPubkeyFromBytes(witness_stack.back(), out);
}

bool ExtractTaprootPubkey(const InputEntryV2& entry, std::array<unsigned char, 33>* out) {
  if (!IsP2TRScriptPubKey(entry.prevout_script_pubkey)) {
    return false;
  }
  std::vector<std::vector<uint8_t>> witness_stack = DecodeTxInWitnessItems(entry.txinwitness);
  if (witness_stack.empty()) {
    return false;
  }
  if (witness_stack.size() > 1 && !witness_stack.back().empty() &&
      witness_stack.back()[0] == 0x50) {
    witness_stack.pop_back();
  }
  if (witness_stack.size() > 1) {
    const std::vector<uint8_t>& control_block = witness_stack.back();
    if (control_block.size() >= 33 &&
        std::equal(kNumsH.begin(), kNumsH.end(), control_block.begin() + 1)) {
      return false;
    }
  }
  out->fill(0);
  (*out)[0] = 0x02;
  std::memcpy(out->data() + 1, entry.prevout_script_pubkey.data() + 2, 32);
  return true;
}

bool ExtractEligibleInput(const InputEntryV2& entry, EligibleInput* out) {
  std::array<unsigned char, 33> pubkey{};
  uint8_t input_type = 0;
  bool eligible = false;
  if (ExtractP2PKHPubkey(entry, &pubkey)) {
    input_type = 0x04;
    eligible = true;
  } else if (ExtractP2SHP2WPKHPubkey(entry, &pubkey)) {
    input_type = 0x03;
    eligible = true;
  } else if (ExtractP2WPKHPubkey(entry, &pubkey)) {
    input_type = 0x01;
    eligible = true;
  } else if (ExtractTaprootPubkey(entry, &pubkey)) {
    input_type = 0x02;
    eligible = true;
  }
  if (!eligible) {
    return false;
  }
  out->input_type = input_type;
  out->pubkey = pubkey;
  out->pubkey_hex = HexEncodeFixed(pubkey.data(), pubkey.size());
  out->is_xonly = input_type == 0x02;
  out->has_privkey = entry.privkey.size() == 32;
  if (out->has_privkey) {
    std::memcpy(out->privkey.data(), entry.privkey.data(), out->privkey.size());
  }
  return true;
}

std::vector<EligibleInput> CollectEligibleInputs(const secp256k1_context* ctx,
                                                 const CaseV2& parsed) {
  std::vector<EligibleInput> eligible_inputs;
  eligible_inputs.reserve(parsed.inputs.size());
  for (const InputEntryV2& entry : parsed.inputs) {
    EligibleInput eligible_input;
    if (!ExtractEligibleInput(entry, &eligible_input)) {
      continue;
    }
    secp256k1_pubkey pubkey;
    if (!ParseCompressedPubkey(ctx, eligible_input.pubkey, &pubkey)) {
      continue;
    }
    eligible_inputs.push_back(std::move(eligible_input));
  }
  return eligible_inputs;
}

void NormalizeTaprootPrivateKey(const secp256k1_context* ctx,
                                std::array<unsigned char, 32>* scalar) {
  secp256k1_pubkey pubkey;
  if (!CreatePubkeyFromScalar(ctx, *scalar, &pubkey)) {
    throw SemanticBridgeError("invalid eligible taproot private key");
  }
  std::array<unsigned char, 33> encoded{};
  if (!SerializeCompressedPubkey(ctx, pubkey, &encoded)) {
    throw SemanticBridgeError("unable to serialize taproot private key");
  }
  if (encoded[0] == 0x03 && secp256k1_ec_seckey_negate(ctx, scalar->data()) != 1) {
    throw SemanticBridgeError("unable to negate taproot private key");
  }
}

bool AddScalarsModOrder(const std::array<unsigned char, 32>& left,
                        const std::array<unsigned char, 32>& right,
                        std::array<unsigned char, 32>* out) {
  const BnCtxPtr ctx(BN_CTX_new());
  const BnPtr order = LoadSecp256k1Order();
  BnPtr lhs(BN_bin2bn(left.data(), static_cast<int>(left.size()), nullptr));
  BnPtr rhs(BN_bin2bn(right.data(), static_cast<int>(right.size()), nullptr));
  BnPtr sum(BN_new());
  if (!ctx || !lhs || !rhs || !sum ||
      BN_mod_add(sum.get(), lhs.get(), rhs.get(), order.get(), ctx.get()) != 1) {
    return false;
  }
  out->fill(0);
  const int width = BN_num_bytes(sum.get());
  if (width < 0 || width > static_cast<int>(out->size())) {
    return false;
  }
  return BN_bn2binpad(sum.get(), out->data(), static_cast<int>(out->size())) ==
         static_cast<int>(out->size());
}

bool BuildSmallestOutpoint(const std::vector<InputEntryV2>& inputs,
                           std::array<unsigned char, 36>* out) {
  if (inputs.empty()) {
    return false;
  }
  bool have_smallest = false;
  std::array<unsigned char, 36> smallest{};
  for (const InputEntryV2& entry : inputs) {
    if (entry.outpoint_txid.size() != 32) {
      return false;
    }
    std::array<unsigned char, 36> candidate{};
    std::memcpy(candidate.data(), entry.outpoint_txid.data(), 32);
    candidate[32] = static_cast<unsigned char>(entry.outpoint_vout & 0xFF);
    candidate[33] = static_cast<unsigned char>((entry.outpoint_vout >> 8) & 0xFF);
    candidate[34] = static_cast<unsigned char>((entry.outpoint_vout >> 16) & 0xFF);
    candidate[35] = static_cast<unsigned char>((entry.outpoint_vout >> 24) & 0xFF);
    if (!have_smallest || candidate < smallest) {
      smallest = candidate;
      have_smallest = true;
    }
  }
  if (!have_smallest) {
    return false;
  }
  *out = smallest;
  return true;
}

bool TaggedHashScalar(const secp256k1_context* ctx, const std::string& tag,
                      const std::vector<unsigned char>& message,
                      std::array<unsigned char, 32>* out) {
  return secp256k1_tagged_sha256(ctx, out->data(),
                                 reinterpret_cast<const unsigned char*>(tag.data()),
                                 tag.size(), message.data(), message.size()) == 1;
}

std::vector<SenderScanGroup> BuildSenderScanGroups(const CaseV2& parsed) {
  std::map<std::string, SenderScanGroup> groups;
  for (const RecipientGroupV2& group : parsed.recipient_groups) {
    if (group.scan_pubkey.size() != 33 || group.spend_pubkey.size() != 33 || group.count == 0) {
      throw SemanticBridgeError("invalid recipient group");
    }
    const std::string scan_hex = HexEncode(group.scan_pubkey);
    SenderScanGroup& aggregate = groups[scan_hex];
    if (aggregate.scan_pubkey_hex.empty()) {
      aggregate.scan_pubkey_hex = scan_hex;
      std::memcpy(aggregate.scan_pubkey.data(), group.scan_pubkey.data(),
                  aggregate.scan_pubkey.size());
    }
    const std::string spend_hex = HexEncode(group.spend_pubkey);
    std::array<unsigned char, 33> spend_pubkey{};
    std::memcpy(spend_pubkey.data(), group.spend_pubkey.data(), spend_pubkey.size());
    for (uint16_t i = 0; i < group.count; ++i) {
      aggregate.spend_pubkeys.push_back(spend_pubkey);
      aggregate.spend_pubkey_hexes.push_back(spend_hex);
    }
  }

  std::vector<SenderScanGroup> ordered;
  ordered.reserve(groups.size());
  for (auto& item : groups) {
    ordered.push_back(std::move(item.second));
  }
  return ordered;
}

void BuildUniquePermutations(std::map<std::string, int>* counts,
                             std::vector<std::string>* path, size_t target_size,
                             std::vector<std::vector<std::string>>* out) {
  if (path->size() == target_size) {
    out->push_back(*path);
    return;
  }
  for (auto& item : *counts) {
    if (item.second == 0) {
      continue;
    }
    item.second -= 1;
    path->push_back(item.first);
    BuildUniquePermutations(counts, path, target_size, out);
    path->pop_back();
    item.second += 1;
  }
}

std::vector<std::vector<std::string>> GenerateUniquePermutations(
    const std::vector<std::string>& items) {
  std::map<std::string, int> counts;
  for (const std::string& item : items) {
    counts[item] += 1;
  }
  std::vector<std::vector<std::string>> permutations;
  std::vector<std::string> path;
  BuildUniquePermutations(&counts, &path, items.size(), &permutations);
  return permutations;
}

JsonArray BuildNullSharedSecrets(const std::vector<SenderScanGroup>& groups) {
  JsonArray shared_secrets;
  for (const SenderScanGroup& group : groups) {
    JsonObject item;
    item["scan_pubkey"] = group.scan_pubkey_hex;
    item["shared_secret"] = nullptr;
    shared_secrets.emplace_back(std::move(item));
  }
  return shared_secrets;
}

void AppendSerUint32(uint32_t value, std::vector<unsigned char>* out) {
  out->push_back(static_cast<unsigned char>((value >> 24) & 0xFF));
  out->push_back(static_cast<unsigned char>((value >> 16) & 0xFF));
  out->push_back(static_cast<unsigned char>((value >> 8) & 0xFF));
  out->push_back(static_cast<unsigned char>(value & 0xFF));
}

uint64_t SplitMix64(uint64_t* state) {
  *state += 0x9e3779b97f4a7c15ULL;
  uint64_t value = *state;
  value = (value ^ (value >> 30U)) * 0xbf58476d1ce4e5b9ULL;
  value = (value ^ (value >> 27U)) * 0x94d049bb133111ebULL;
  return value ^ (value >> 31U);
}

void FillDeterministicBytes(uint64_t* state, unsigned char* out, size_t size) {
  for (size_t offset = 0; offset < size; offset += sizeof(uint64_t)) {
    const uint64_t value = SplitMix64(state);
    const size_t chunk = std::min(sizeof(uint64_t), size - offset);
    std::memcpy(out + offset, &value, chunk);
  }
}

std::array<unsigned char, 32> RandomValidScalar(const secp256k1_context* ctx, uint64_t* state) {
  while (true) {
    std::array<unsigned char, 32> scalar{};
    FillDeterministicBytes(state, scalar.data(), scalar.size());
    if (VerifyScalar(ctx, scalar)) {
      return scalar;
    }
  }
}

std::vector<uint8_t> EncodeCompactSizeValue(uint64_t value) {
  std::vector<uint8_t> out;
  if (value < 253) {
    out.push_back(static_cast<uint8_t>(value));
    return out;
  }
  if (value <= 0xFFFF) {
    out.push_back(253);
    out.push_back(static_cast<uint8_t>(value & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    return out;
  }
  if (value <= 0xFFFFFFFFULL) {
    out.push_back(254);
    for (size_t i = 0; i < 4; ++i) {
      out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
    }
    return out;
  }
  out.push_back(255);
  for (size_t i = 0; i < 8; ++i) {
    out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
  }
  return out;
}

std::vector<uint8_t> EncodeWitnessWithSingleItem(const std::vector<uint8_t>& item) {
  std::vector<uint8_t> out;
  out.reserve(2 + item.size());
  out.push_back(0x01);
  const std::vector<uint8_t> length = EncodeCompactSizeValue(item.size());
  out.insert(out.end(), length.begin(), length.end());
  out.insert(out.end(), item.begin(), item.end());
  return out;
}

InputEntryV2 BuildSyntheticTaprootInput(const secp256k1_context* ctx,
                                        const std::array<unsigned char, 32>& taproot_privkey,
                                        uint64_t* state) {
  std::array<unsigned char, 32> normalized_privkey = taproot_privkey;
  NormalizeTaprootPrivateKey(ctx, &normalized_privkey);

  secp256k1_pubkey pubkey;
  if (!CreatePubkeyFromScalar(ctx, normalized_privkey, &pubkey)) {
    throw SemanticBridgeError("unable to build synthetic taproot pubkey");
  }
  std::array<unsigned char, 33> encoded_pubkey{};
  if (!SerializeCompressedPubkey(ctx, pubkey, &encoded_pubkey)) {
    throw SemanticBridgeError("unable to serialize synthetic taproot pubkey");
  }

  InputEntryV2 entry;
  entry.outpoint_txid.resize(32);
  FillDeterministicBytes(state, entry.outpoint_txid.data(), entry.outpoint_txid.size());
  entry.outpoint_vout = static_cast<uint32_t>(SplitMix64(state));
  entry.input_type = 0x02;
  entry.prevout_script_pubkey = {0x51, 0x20};
  entry.prevout_script_pubkey.insert(entry.prevout_script_pubkey.end(),
                                     encoded_pubkey.begin() + 1, encoded_pubkey.end());
  entry.script_sig.clear();
  entry.txinwitness = EncodeWitnessWithSingleItem(std::vector<uint8_t>(64, 0x00));
  entry.privkey.assign(normalized_privkey.begin(), normalized_privkey.end());
  entry.pubkey.assign(encoded_pubkey.begin(), encoded_pubkey.end());
  return entry;
}

std::array<unsigned char, 32> SumEligiblePrivateKeys(
    const secp256k1_context* ctx, const std::vector<EligibleInput>& eligible_inputs) {
  bool have_any = false;
  std::array<unsigned char, 32> sum{};
  for (const EligibleInput& input : eligible_inputs) {
    if (!input.has_privkey) {
      continue;
    }
    std::array<unsigned char, 32> scalar = input.privkey;
    if (!VerifyScalar(ctx, scalar)) {
      throw SemanticBridgeError("invalid eligible input private key");
    }
    if (input.is_xonly) {
      NormalizeTaprootPrivateKey(ctx, &scalar);
    }
    if (!have_any) {
      sum = scalar;
      have_any = true;
      continue;
    }
    if (!AddScalarsModOrder(sum, scalar, &sum)) {
      throw SemanticBridgeError("unable to aggregate eligible input private keys");
    }
  }
  if (!have_any) {
    throw SemanticBridgeError("send case is missing eligible private keys");
  }
  return sum;
}

std::array<unsigned char, 32> ComputeSenderInputHash(
    const secp256k1_context* ctx, const CaseV2& parsed,
    const std::array<unsigned char, 32>& input_private_key_sum) {
  secp256k1_pubkey sum_pubkey;
  if (!CreatePubkeyFromScalar(ctx, input_private_key_sum, &sum_pubkey)) {
    throw SemanticBridgeError("unable to build aggregate input pubkey");
  }
  std::array<unsigned char, 33> encoded_sum{};
  if (!SerializeCompressedPubkey(ctx, sum_pubkey, &encoded_sum)) {
    throw SemanticBridgeError("unable to serialize aggregate input pubkey");
  }
  std::array<unsigned char, 36> smallest_outpoint{};
  if (!BuildSmallestOutpoint(parsed.inputs, &smallest_outpoint)) {
    throw SemanticBridgeError("unable to determine lexicographically smallest outpoint");
  }
  std::vector<unsigned char> message;
  message.reserve(smallest_outpoint.size() + encoded_sum.size());
  message.insert(message.end(), smallest_outpoint.begin(), smallest_outpoint.end());
  message.insert(message.end(), encoded_sum.begin(), encoded_sum.end());
  std::array<unsigned char, 32> input_hash{};
  if (!TaggedHashScalar(ctx, "BIP0352/Inputs", message, &input_hash)) {
    throw SemanticBridgeError("unable to compute input_hash");
  }
  if (!VerifyScalar(ctx, input_hash)) {
    throw SemanticBridgeError("input_hash was not a valid scalar");
  }
  return input_hash;
}

std::array<unsigned char, 32> ComputeInputHashFromCompressedSum(
    const secp256k1_context* ctx, const CaseV2& parsed,
    const std::array<unsigned char, 33>& encoded_sum) {
  std::array<unsigned char, 36> smallest_outpoint{};
  if (!BuildSmallestOutpoint(parsed.inputs, &smallest_outpoint)) {
    throw SemanticBridgeError("unable to determine lexicographically smallest outpoint");
  }
  std::vector<unsigned char> message;
  message.reserve(smallest_outpoint.size() + encoded_sum.size());
  message.insert(message.end(), smallest_outpoint.begin(), smallest_outpoint.end());
  message.insert(message.end(), encoded_sum.begin(), encoded_sum.end());
  std::array<unsigned char, 32> input_hash{};
  if (!TaggedHashScalar(ctx, "BIP0352/Inputs", message, &input_hash)) {
    throw SemanticBridgeError("unable to compute input_hash");
  }
  if (!VerifyScalar(ctx, input_hash)) {
    throw SemanticBridgeError("input_hash was not a valid scalar");
  }
  return input_hash;
}

std::array<unsigned char, 33> MultiplyPubkeyByScalar(
    const secp256k1_context* ctx, const std::array<unsigned char, 33>& encoded_pubkey,
    const std::array<unsigned char, 32>& scalar) {
  secp256k1_pubkey pubkey;
  if (!ParseCompressedPubkey(ctx, encoded_pubkey, &pubkey)) {
    throw SemanticBridgeError("invalid compressed public key");
  }
  if (secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, scalar.data()) != 1) {
    throw SemanticBridgeError("unable to multiply public key by scalar");
  }
  std::array<unsigned char, 33> encoded{};
  if (!SerializeCompressedPubkey(ctx, pubkey, &encoded)) {
    throw SemanticBridgeError("unable to serialize multiplied public key");
  }
  return encoded;
}

std::array<unsigned char, 33> MultiplyPubkeyByScalars(
    const secp256k1_context* ctx, const std::array<unsigned char, 33>& encoded_pubkey,
    const std::array<unsigned char, 32>& left, const std::array<unsigned char, 32>& right) {
  secp256k1_pubkey pubkey;
  if (!ParseCompressedPubkey(ctx, encoded_pubkey, &pubkey)) {
    throw SemanticBridgeError("invalid compressed public key");
  }
  if (secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, left.data()) != 1 ||
      secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, right.data()) != 1) {
    throw SemanticBridgeError("unable to multiply public key by scalar");
  }
  std::array<unsigned char, 33> encoded{};
  if (!SerializeCompressedPubkey(ctx, pubkey, &encoded)) {
    throw SemanticBridgeError("unable to serialize multiplied public key");
  }
  return encoded;
}

JsonArray ComputeSharedSecrets(const secp256k1_context* ctx,
                               const std::vector<SenderScanGroup>& groups,
                               const std::array<unsigned char, 32>& input_private_key_sum,
                               const std::array<unsigned char, 32>& input_hash) {
  JsonArray shared_secrets;
  for (const SenderScanGroup& group : groups) {
    const std::array<unsigned char, 33> shared_secret =
        MultiplyPubkeyByScalars(ctx, group.scan_pubkey, input_private_key_sum, input_hash);
    JsonObject item;
    item["scan_pubkey"] = group.scan_pubkey_hex;
    item["shared_secret"] = HexEncodeFixed(shared_secret.data(), shared_secret.size());
    shared_secrets.emplace_back(std::move(item));
  }
  return shared_secrets;
}

std::set<std::vector<std::string>> ComputeOutputSetsForGroup(
    const secp256k1_context* ctx, const SenderScanGroup& group,
    const std::array<unsigned char, 32>& input_private_key_sum,
    const std::array<unsigned char, 32>& input_hash) {
  const std::array<unsigned char, 33> shared_secret =
      MultiplyPubkeyByScalars(ctx, group.scan_pubkey, input_private_key_sum, input_hash);

  std::map<std::string, std::array<unsigned char, 33>> spend_lookup;
  for (size_t i = 0; i < group.spend_pubkey_hexes.size(); ++i) {
    spend_lookup[group.spend_pubkey_hexes[i]] = group.spend_pubkeys[i];
  }

  std::set<std::vector<std::string>> output_sets;
  const std::vector<std::vector<std::string>> permutations =
      GenerateUniquePermutations(group.spend_pubkey_hexes);
  for (const std::vector<std::string>& permutation : permutations) {
    std::set<std::string> outputs;
    for (size_t index = 0; index < permutation.size(); ++index) {
      std::vector<unsigned char> message;
      message.reserve(shared_secret.size() + 4);
      message.insert(message.end(), shared_secret.begin(), shared_secret.end());
      AppendSerUint32(static_cast<uint32_t>(index), &message);

      std::array<unsigned char, 32> tweak{};
      if (!TaggedHashScalar(ctx, "BIP0352/SharedSecret", message, &tweak)) {
        throw SemanticBridgeError("unable to derive sender output tweak");
      }
      if (!VerifyScalar(ctx, tweak)) {
        throw SemanticBridgeError("sender output tweak was not a valid scalar");
      }

      secp256k1_pubkey spend_pubkey;
      if (!ParseCompressedPubkey(ctx, spend_lookup.at(permutation[index]), &spend_pubkey)) {
        throw SemanticBridgeError("invalid recipient spend pubkey");
      }
      if (secp256k1_ec_pubkey_tweak_add(ctx, &spend_pubkey, tweak.data()) != 1) {
        throw SemanticBridgeError("unable to tweak recipient spend pubkey");
      }
      std::array<unsigned char, 33> output_pubkey{};
      if (!SerializeCompressedPubkey(ctx, spend_pubkey, &output_pubkey)) {
        throw SemanticBridgeError("unable to serialize sender output pubkey");
      }
      outputs.insert(HexEncodeFixed(output_pubkey.data() + 1, 32));
    }
    output_sets.insert(std::vector<std::string>(outputs.begin(), outputs.end()));
  }
  return output_sets;
}

JsonObject DeriveNativeSendSemanticResultObject(const CaseV2& parsed,
                                                const JsonObject& source) {
  if (parsed.recipient_groups.empty()) {
    throw SemanticBridgeError("send case is missing recipient_groups");
  }

  const SecpContextPtr secp = CreateSecpContext();
  const std::vector<SenderScanGroup> scan_groups = BuildSenderScanGroups(parsed);

  JsonObject result;
  result["semantic_contract_version"] = kSemanticContractVersion;
  result["case_format_version"] = static_cast<int64_t>(2);
  result["kind"] = "send";
  result["source"] = source;
  result["notes"] = JsonArray{};

  JsonArray input_pubkeys;
  const std::vector<EligibleInput> eligible_inputs = CollectEligibleInputs(secp.get(), parsed);
  for (const EligibleInput& eligible_input : eligible_inputs) {
    input_pubkeys.emplace_back(eligible_input.pubkey_hex);
  }
  result["input_pubkeys"] = input_pubkeys;
  result["sender_shared_secrets"] = BuildNullSharedSecrets(scan_groups);
  result["acceptable_output_sets"] = JsonArray{JsonValue(JsonArray{})};
  result["output_count_options"] = JsonArray{JsonValue(static_cast<int64_t>(0))};
  result["input_hash"] = nullptr;
  result["input_private_key_sum"] = nullptr;

  if (eligible_inputs.empty()) {
    result["semantic_status"] = "no_eligible_inputs";
    return result;
  }

  const std::array<unsigned char, 32> input_private_key_sum =
      SumEligiblePrivateKeys(secp.get(), eligible_inputs);
  result["input_private_key_sum"] =
      HexEncodeFixed(input_private_key_sum.data(), input_private_key_sum.size());

  if (ScalarIsZero(input_private_key_sum)) {
    result["semantic_status"] = "zero_scalar";
    return result;
  }

  const std::array<unsigned char, 32> input_hash =
      ComputeSenderInputHash(secp.get(), parsed, input_private_key_sum);
  result["input_hash"] = HexEncodeFixed(input_hash.data(), input_hash.size());

  for (const SenderScanGroup& group : scan_groups) {
    if (group.spend_pubkeys.size() > kRecipientLimit) {
      result["semantic_status"] = "recipient_limit_exceeded";
      result["notes"] = JsonArray{JsonValue("per_group_recipient_limit_exceeded")};
      return result;
    }
  }

  result["semantic_status"] = "ok";
  result["sender_shared_secrets"] =
      ComputeSharedSecrets(secp.get(), scan_groups, input_private_key_sum, input_hash);

  std::set<std::vector<std::string>> full_sets;
  full_sets.insert(std::vector<std::string>{});
  for (const SenderScanGroup& group : scan_groups) {
    const std::set<std::vector<std::string>> group_sets =
        ComputeOutputSetsForGroup(secp.get(), group, input_private_key_sum, input_hash);
    std::set<std::vector<std::string>> next_sets;
    for (const std::vector<std::string>& prefix : full_sets) {
      std::set<std::string> prefix_items(prefix.begin(), prefix.end());
      for (const std::vector<std::string>& output_set : group_sets) {
        std::set<std::string> merged(prefix_items.begin(), prefix_items.end());
        merged.insert(output_set.begin(), output_set.end());
        next_sets.insert(std::vector<std::string>(merged.begin(), merged.end()));
      }
    }
    full_sets.swap(next_sets);
  }

  JsonArray acceptable_output_sets;
  std::set<int64_t> output_count_options;
  for (const std::vector<std::string>& output_set : full_sets) {
    JsonArray items;
    for (const std::string& output : output_set) {
      items.emplace_back(output);
    }
    output_count_options.insert(static_cast<int64_t>(output_set.size()));
    acceptable_output_sets.emplace_back(std::move(items));
  }
  JsonArray count_options;
  for (int64_t count : output_count_options) {
    count_options.emplace_back(count);
  }
  result["acceptable_output_sets"] = std::move(acceptable_output_sets);
  result["output_count_options"] = std::move(count_options);
  return result;
}

std::array<unsigned char, 32> ComputeLabelTweak(const secp256k1_context* ctx,
                                                const std::array<unsigned char, 32>& scan_privkey,
                                                uint32_t label) {
  std::vector<unsigned char> message(scan_privkey.begin(), scan_privkey.end());
  AppendSerUint32(label, &message);
  std::array<unsigned char, 32> tweak{};
  if (!TaggedHashScalar(ctx, "BIP0352/Label", message, &tweak) || !VerifyScalar(ctx, tweak)) {
    throw SemanticBridgeError("unable to derive label tweak");
  }
  return tweak;
}

JsonArray BuildReceivingAddresses(const secp256k1_context* ctx, const CaseV2& parsed,
                                  const std::array<unsigned char, 32>& scan_privkey,
                                  const std::array<unsigned char, 32>& spend_privkey,
                                  const std::string& network,
                                  uint32_t silent_payment_version) {
  secp256k1_pubkey scan_pubkey;
  secp256k1_pubkey spend_pubkey;
  if (!CreatePubkeyFromScalar(ctx, scan_privkey, &scan_pubkey) ||
      !CreatePubkeyFromScalar(ctx, spend_privkey, &spend_pubkey)) {
    throw SemanticBridgeError("invalid receiver key material");
  }
  std::array<unsigned char, 33> scan_encoded{};
  std::array<unsigned char, 33> spend_encoded{};
  if (!SerializeCompressedPubkey(ctx, scan_pubkey, &scan_encoded) ||
      !SerializeCompressedPubkey(ctx, spend_pubkey, &spend_encoded)) {
    throw SemanticBridgeError("unable to serialize receiver key material");
  }

  JsonArray addresses;
  addresses.emplace_back(
      EncodeSilentPaymentAddress(scan_encoded, spend_encoded, network, silent_payment_version));
  for (uint32_t label : parsed.labels) {
    const std::array<unsigned char, 32> label_tweak =
        ComputeLabelTweak(ctx, scan_privkey, label);
    secp256k1_pubkey labeled_spend = spend_pubkey;
    if (secp256k1_ec_pubkey_tweak_add(ctx, &labeled_spend, label_tweak.data()) != 1) {
      throw SemanticBridgeError("unable to apply label tweak");
    }
    std::array<unsigned char, 33> labeled_spend_encoded{};
    if (!SerializeCompressedPubkey(ctx, labeled_spend, &labeled_spend_encoded)) {
      throw SemanticBridgeError("unable to serialize labeled spend pubkey");
    }
    addresses.emplace_back(EncodeSilentPaymentAddress(scan_encoded, labeled_spend_encoded,
                                                      network, silent_payment_version));
  }
  return addresses;
}

std::map<std::string, std::array<unsigned char, 32>> BuildReceiveLabelMap(
    const secp256k1_context* ctx, const std::array<unsigned char, 32>& scan_privkey,
    const std::vector<uint32_t>& labels) {
  std::map<std::string, std::array<unsigned char, 32>> label_map;
  for (uint32_t label : labels) {
    const std::array<unsigned char, 32> label_tweak =
        ComputeLabelTweak(ctx, scan_privkey, label);
    secp256k1_pubkey label_pubkey;
    if (!CreatePubkeyFromScalar(ctx, label_tweak, &label_pubkey)) {
      throw SemanticBridgeError("unable to create label pubkey");
    }
    std::array<unsigned char, 33> label_encoded{};
    if (!SerializeCompressedPubkey(ctx, label_pubkey, &label_encoded)) {
      throw SemanticBridgeError("unable to serialize label pubkey");
    }
    label_map[HexEncodeFixed(label_encoded.data(), label_encoded.size())] = label_tweak;
  }
  return label_map;
}

bool SumEligibleInputPubkeys(const secp256k1_context* ctx,
                             const std::vector<EligibleInput>& eligible_inputs,
                             secp256k1_pubkey* sum_pubkey,
                             std::array<unsigned char, 33>* encoded_sum) {
  std::vector<secp256k1_pubkey> parsed_pubkeys;
  parsed_pubkeys.reserve(eligible_inputs.size());
  for (const EligibleInput& input : eligible_inputs) {
    secp256k1_pubkey pubkey;
    if (!ParseCompressedPubkey(ctx, input.pubkey, &pubkey)) {
      continue;
    }
    parsed_pubkeys.push_back(pubkey);
  }
  if (parsed_pubkeys.empty()) {
    return false;
  }
  if (!CombinePubkeys(ctx, parsed_pubkeys, sum_pubkey)) {
    return false;
  }
  return SerializeCompressedPubkey(ctx, *sum_pubkey, encoded_sum);
}

ReceiveScanCoreResult ComputeReceiveScanCore(const secp256k1_context* ctx, const CaseV2& parsed,
                                             const std::array<unsigned char, 32>& scan_privkey,
                                             const std::array<unsigned char, 32>& spend_privkey) {
  ReceiveScanCoreResult result;
  const std::vector<EligibleInput> eligible_inputs = CollectEligibleInputs(ctx, parsed);
  for (const EligibleInput& eligible_input : eligible_inputs) {
    result.input_pubkeys.emplace_back(eligible_input.pubkey_hex);
  }
  if (eligible_inputs.empty()) {
    result.semantic_status = "no_eligible_inputs";
    return result;
  }

  secp256k1_pubkey input_pubkey_sum;
  if (!SumEligibleInputPubkeys(ctx, eligible_inputs, &input_pubkey_sum,
                               &result.input_pubkey_sum)) {
    result.semantic_status = "point_at_infinity";
    return result;
  }
  result.has_input_pubkey_sum = true;

  result.input_hash = ComputeInputHashFromCompressedSum(ctx, parsed, result.input_pubkey_sum);
  result.has_input_hash = true;
  result.tweak = MultiplyPubkeyByScalar(ctx, result.input_pubkey_sum, result.input_hash);
  result.has_tweak = true;
  result.shared_secret =
      MultiplyPubkeyByScalars(ctx, result.input_pubkey_sum, result.input_hash, scan_privkey);
  result.has_shared_secret = true;
  if (!CreatePubkeyFromScalar(ctx, spend_privkey, &result.spend_pubkey)) {
    throw SemanticBridgeError("unable to derive spend pubkey");
  }
  result.has_spend_pubkey = true;
  return result;
}

bool DeriveReceiveCandidate(const secp256k1_context* ctx, const secp256k1_pubkey& spend_pubkey,
                            const std::array<unsigned char, 33>& shared_secret, uint32_t index,
                            secp256k1_pubkey* candidate,
                            std::array<unsigned char, 32>* tweak) {
  std::vector<unsigned char> message(shared_secret.begin(), shared_secret.end());
  AppendSerUint32(index, &message);
  if (!TaggedHashScalar(ctx, "BIP0352/SharedSecret", message, tweak) ||
      !VerifyScalar(ctx, *tweak)) {
    return false;
  }

  *candidate = spend_pubkey;
  return secp256k1_ec_pubkey_tweak_add(ctx, candidate, tweak->data()) == 1;
}

JsonObject MakeFoundOutput(const secp256k1_context* ctx, const secp256k1_pubkey& output_pubkey,
                           const std::array<unsigned char, 32>& private_key_tweak) {
  std::array<unsigned char, 32> xonly{};
  if (!SerializeXOnlyPubkey(ctx, output_pubkey, &xonly)) {
    throw SemanticBridgeError("unable to serialize found output");
  }
  JsonObject found;
  found["pub_key"] = HexEncodeFixed(xonly.data(), xonly.size());
  found["priv_key_tweak"] =
      HexEncodeFixed(private_key_tweak.data(), private_key_tweak.size());
  return found;
}

JsonArray ScanReceiveOutputs(const secp256k1_context* ctx, const CaseV2& parsed,
                             const secp256k1_pubkey& spend_pubkey,
                             const std::array<unsigned char, 33>& shared_secret,
                             const std::map<std::string, std::array<unsigned char, 32>>& label_map,
                             bool record_found_outputs, int64_t* found_output_count) {
  std::vector<bool> consumed(parsed.outputs_to_scan.size(), false);
  JsonArray found_outputs;
  int64_t count = 0;
  for (uint32_t k = 0; k < kRecipientLimit; ++k) {
    std::array<unsigned char, 32> tweak{};
    secp256k1_pubkey candidate;
    if (!DeriveReceiveCandidate(ctx, spend_pubkey, shared_secret, k, &candidate, &tweak)) {
      throw SemanticBridgeError("receive tweak was not a valid scalar");
    }
    std::array<unsigned char, 32> candidate_xonly{};
    if (!SerializeXOnlyPubkey(ctx, candidate, &candidate_xonly)) {
      throw SemanticBridgeError("unable to serialize receive output candidate");
    }

    bool matched = false;
    for (size_t i = 0; i < parsed.outputs_to_scan.size(); ++i) {
      if (consumed[i]) {
        continue;
      }
      const std::vector<uint8_t>& output = parsed.outputs_to_scan[i];
      if (output.size() != 32) {
        throw SemanticBridgeError("invalid outputs_to_scan entry");
      }
      if (std::equal(candidate_xonly.begin(), candidate_xonly.end(), output.begin())) {
        if (record_found_outputs) {
          found_outputs.emplace_back(MakeFoundOutput(ctx, candidate, tweak));
        }
        consumed[i] = true;
        matched = true;
        count += 1;
        break;
      }
      if (label_map.empty()) {
        continue;
      }

      std::array<unsigned char, 32> output_xonly{};
      std::memcpy(output_xonly.data(), output.data(), output_xonly.size());
      secp256k1_pubkey output_pubkey;
      if (!ParseXOnlyPubkey(ctx, output_xonly, &output_pubkey)) {
        throw SemanticBridgeError("invalid outputs_to_scan xonly pubkey");
      }

      auto try_label_match = [&](const secp256k1_pubkey& lhs) -> bool {
        const secp256k1_pubkey label_point = SubtractPubkeys(ctx, lhs, candidate);
        std::array<unsigned char, 33> label_encoded{};
        if (!SerializeCompressedPubkey(ctx, label_point, &label_encoded)) {
          throw SemanticBridgeError("unable to serialize label point");
        }
        const auto label_it =
            label_map.find(HexEncodeFixed(label_encoded.data(), label_encoded.size()));
        if (label_it == label_map.end()) {
          return false;
        }
        std::array<unsigned char, 32> full_tweak{};
        if (!AddScalarsModOrder(tweak, label_it->second, &full_tweak)) {
          throw SemanticBridgeError("unable to aggregate receive tweaks");
        }
        const secp256k1_pubkey labeled_output = AddPubkeys(ctx, candidate, label_point);
        if (record_found_outputs) {
          found_outputs.emplace_back(MakeFoundOutput(ctx, labeled_output, full_tweak));
        }
        consumed[i] = true;
        matched = true;
        count += 1;
        return true;
      };

      if (try_label_match(output_pubkey)) {
        break;
      }
      if (try_label_match(NegatedPubkey(ctx, output_pubkey))) {
        break;
      }
    }
    if (!matched) {
      break;
    }
  }
  *found_output_count = count;
  return found_outputs;
}

JsonObject DeriveNativeReceiveSemanticResultObject(
    const CaseV2& parsed, const JsonObject& source, bool detailed_outputs_available,
    const NativeSemanticOptions& options) {
  if (parsed.receiver_keys.scan_privkey.size() != 32 ||
      parsed.receiver_keys.spend_privkey.size() != 32) {
    throw SemanticBridgeError("receive case is missing receiver key material");
  }

  const SecpContextPtr secp = CreateSecpContext();
  const std::array<unsigned char, 32> scan_privkey =
      HexToArray32(HexEncode(parsed.receiver_keys.scan_privkey));
  const std::array<unsigned char, 32> spend_privkey =
      HexToArray32(HexEncode(parsed.receiver_keys.spend_privkey));
  if (!VerifyScalar(secp.get(), scan_privkey) || !VerifyScalar(secp.get(), spend_privkey)) {
    throw SemanticBridgeError("invalid receiver private key");
  }

  JsonObject result;
  result["semantic_contract_version"] = kSemanticContractVersion;
  result["case_format_version"] = static_cast<int64_t>(2);
  result["kind"] = "receive";
  result["source"] = source;
  result["notes"] = JsonArray{};
  result["receiving_addresses"] = BuildReceivingAddresses(secp.get(), parsed, scan_privkey,
                                                          spend_privkey, options.network,
                                                          options.silent_payment_version);
  result["input_hash"] = nullptr;
  result["input_pubkey_sum"] = nullptr;
  result["tweak"] = nullptr;
  result["shared_secret"] = nullptr;
  result["detailed_outputs_available"] = detailed_outputs_available;
  result["found_output_count"] = static_cast<int64_t>(0);
  result["found_outputs"] = JsonArray{};

  const ReceiveScanCoreResult core =
      ComputeReceiveScanCore(secp.get(), parsed, scan_privkey, spend_privkey);
  result["input_pubkeys"] = core.input_pubkeys;
  if (core.semantic_status != "ok") {
    result["semantic_status"] = core.semantic_status;
    return result;
  }

  result["semantic_status"] = "ok";
  result["input_pubkey_sum"] =
      HexEncodeFixed(core.input_pubkey_sum.data(), core.input_pubkey_sum.size());
  result["input_hash"] = HexEncodeFixed(core.input_hash.data(), core.input_hash.size());
  result["tweak"] = HexEncodeFixed(core.tweak.data(), core.tweak.size());
  result["shared_secret"] =
      HexEncodeFixed(core.shared_secret.data(), core.shared_secret.size());
  const std::map<std::string, std::array<unsigned char, 32>> label_map =
      BuildReceiveLabelMap(secp.get(), scan_privkey, parsed.labels);

  int64_t found_output_count = 0;
  const JsonArray found_outputs =
      ScanReceiveOutputs(secp.get(), parsed, core.spend_pubkey, core.shared_secret, label_map,
                         detailed_outputs_available, &found_output_count);
  result["found_output_count"] = found_output_count;
  if (detailed_outputs_available) {
    result["found_outputs"] = found_outputs;
  }
  JsonArray notes = JsonArray{};
  if (parsed.outputs_to_scan.size() > kRecipientLimit &&
      found_output_count == static_cast<int64_t>(kRecipientLimit)) {
    notes.emplace_back("scan_limit_reached");
  }
  if (!detailed_outputs_available) {
    notes.emplace_back("count_only_expectation");
  }
  result["notes"] = notes;
  return result;
}

std::vector<BenchmarkDensityProfile> ResolveBenchmarkProfiles(const std::string& density) {
  static const std::array<BenchmarkDensityProfile, 3> kProfiles = {
      BenchmarkDensityProfile{"sparse", 4},
      BenchmarkDensityProfile{"medium", 16},
      BenchmarkDensityProfile{"dense", 64},
  };
  if (density == "all") {
    return std::vector<BenchmarkDensityProfile>(kProfiles.begin(), kProfiles.end());
  }
  for (const BenchmarkDensityProfile& profile : kProfiles) {
    if (density == profile.name) {
      return {profile};
    }
  }
  throw SemanticBridgeError("unknown benchmark density");
}

uint32_t ResolveBenchmarkThreadCount(uint32_t requested, uint64_t work_items) {
  const uint32_t detected = std::max<uint32_t>(1, std::thread::hardware_concurrency());
  const uint32_t limit = static_cast<uint32_t>(
      std::min<uint64_t>(std::max<uint64_t>(1, work_items), static_cast<uint64_t>(detected)));
  if (requested == 0) {
    return limit;
  }
  return std::max<uint32_t>(1, std::min<uint32_t>(requested, limit));
}

CaseV2 BuildSyntheticReceiveBenchmarkCase(const secp256k1_context* ctx,
                                          const std::array<unsigned char, 32>& scan_privkey,
                                          const std::array<unsigned char, 32>& spend_privkey,
                                          uint32_t outputs_per_transaction,
                                          uint64_t transaction_index, uint64_t* state) {
  CaseV2 parsed;
  parsed.inputs.push_back(
      BuildSyntheticTaprootInput(ctx, RandomValidScalar(ctx, state), state));
  parsed.receiver_keys.scan_privkey.assign(scan_privkey.begin(), scan_privkey.end());
  parsed.receiver_keys.spend_privkey.assign(spend_privkey.begin(), spend_privkey.end());

  const ReceiveScanCoreResult core =
      ComputeReceiveScanCore(ctx, parsed, scan_privkey, spend_privkey);
  if (core.semantic_status != "ok") {
    throw SemanticBridgeError("unable to build synthetic receive benchmark case");
  }

  parsed.outputs_to_scan.resize(outputs_per_transaction);
  for (uint32_t i = 0; i < outputs_per_transaction; ++i) {
    parsed.outputs_to_scan[i].resize(32);
    FillDeterministicBytes(state, parsed.outputs_to_scan[i].data(),
                           parsed.outputs_to_scan[i].size());
  }

  uint32_t match_count = 0;
  if ((transaction_index % 3) == 0) {
    match_count = 1;
  }
  if (outputs_per_transaction >= 32 && (transaction_index % 11) == 0) {
    match_count = 2;
  }
  match_count = std::min(match_count, outputs_per_transaction);
  for (uint32_t index = 0; index < match_count; ++index) {
    secp256k1_pubkey candidate;
    std::array<unsigned char, 32> tweak{};
    if (!DeriveReceiveCandidate(ctx, core.spend_pubkey, core.shared_secret, index, &candidate,
                                &tweak)) {
      throw SemanticBridgeError("unable to derive synthetic receive candidate");
    }
    std::array<unsigned char, 32> output_xonly{};
    if (!SerializeXOnlyPubkey(ctx, candidate, &output_xonly)) {
      throw SemanticBridgeError("unable to serialize synthetic receive candidate");
    }
    std::vector<uint8_t> encoded(output_xonly.begin(), output_xonly.end());
    parsed.outputs_to_scan[outputs_per_transaction - match_count + index] = std::move(encoded);
  }
  return parsed;
}

void RunSyntheticReceiveBenchmarkRange(const std::vector<CaseV2>& cases, size_t begin, size_t end,
                                       uint64_t* matched_transactions,
                                       uint64_t* found_outputs, std::string* error) {
  try {
    const SecpContextPtr secp = CreateSecpContext();
    for (size_t index = begin; index < end; ++index) {
      const CaseV2& parsed = cases[index];
      const std::array<unsigned char, 32> scan_privkey =
          BytesToArray32(parsed.receiver_keys.scan_privkey, "receiver scan_privkey");
      const std::array<unsigned char, 32> spend_privkey =
          BytesToArray32(parsed.receiver_keys.spend_privkey, "receiver spend_privkey");
      const ReceiveScanCoreResult core =
          ComputeReceiveScanCore(secp.get(), parsed, scan_privkey, spend_privkey);
      if (core.semantic_status != "ok") {
        throw SemanticBridgeError("synthetic receive benchmark case lost semantic parity");
      }
      int64_t found_output_count = 0;
      const std::map<std::string, std::array<unsigned char, 32>> empty_label_map;
      ScanReceiveOutputs(secp.get(), parsed, core.spend_pubkey, core.shared_secret,
                         empty_label_map, false, &found_output_count);
      if (found_output_count > 0) {
        *matched_transactions += 1;
      }
      *found_outputs += static_cast<uint64_t>(found_output_count);
    }
  } catch (const std::exception& exception) {
    if (error != nullptr) {
      *error = exception.what();
    }
  }
}

JsonObject BuildSourceFromCaseStem(const std::filesystem::path& case_path,
                                   const std::string& kind) {
  std::smatch match;
  const std::string stem = case_path.stem().string();
  if (std::regex_match(stem, match, kOfficialCaseRegex)) {
    JsonObject source;
    source["kind"] = match[2].str();
    source["comment"] = stem;
    source["case_index"] = static_cast<int64_t>(std::stoll(match[1].str()));
    source["entry_index"] = static_cast<int64_t>(std::stoll(match[3].str()));
    source["id"] = stem;
    return source;
  }

  JsonObject source;
  source["kind"] = kind;
  source["comment"] = case_path.filename().string();
  source["case_index"] = static_cast<int64_t>(0);
  source["entry_index"] = static_cast<int64_t>(0);
  source["id"] = stem;
  return source;
}

std::string InferKind(const CaseV2& parsed) {
  const bool has_send_fields = !parsed.recipient_groups.empty();
  const bool has_receive_fields = !parsed.outputs_to_scan.empty() || !parsed.labels.empty() ||
                                  !parsed.receiver_keys.scan_privkey.empty() ||
                                  !parsed.receiver_keys.spend_privkey.empty();
  if (has_send_fields && !has_receive_fields) {
    return "send";
  }
  if (has_receive_fields && !has_send_fields) {
    return "receive";
  }
  throw SemanticBridgeError("unable to infer semantic kind from v2 case");
}

JsonObject BuildRequestObject(const std::filesystem::path& case_path, const CaseV2& parsed,
                              const SemanticRequestOptions& options) {
  if (!IsKnownNetwork(options.network)) {
    throw SemanticBridgeError("unknown network");
  }

  std::string resolved_expectation = options.expectation_path;
  if (resolved_expectation.empty()) {
    std::filesystem::path candidate = case_path;
    candidate.replace_extension(".expected.json");
    if (std::filesystem::exists(candidate)) {
      resolved_expectation = candidate.string();
    }
  }

  std::string request_kind = options.kind;
  JsonObject source;
  bool detailed_outputs_required = true;
  bool has_expectation_hints = false;

  if (!resolved_expectation.empty()) {
    const JsonValue expected_value = ValidateSemanticResultValue(ParseJsonFile(resolved_expectation));
    const JsonObject& expected = expected_value.as_object();
    request_kind = expected.at("kind").as_string();
    source = expected.at("source").as_object();
    if (request_kind == "receive") {
      detailed_outputs_required =
          expected.at("detailed_outputs_available").as_bool();
      has_expectation_hints = true;
    }
  } else {
    if (request_kind == "auto") {
      request_kind = InferKind(parsed);
    }
    if (!IsKnownKind(request_kind)) {
      throw SemanticBridgeError("unknown kind");
    }
    source = BuildSourceFromCaseStem(case_path, request_kind);
  }

  JsonObject request;
  request["semantic_adapter_request_version"] = kSemanticAdapterRequestVersion;
  request["case_format_version"] = static_cast<int64_t>(2);
  request["kind"] = request_kind;
  request["network"] = options.network;
  request["silent_payment_version"] =
      static_cast<int64_t>(options.silent_payment_version);
  request["seed"] = parsed.header.seed;
  request["flags"] = static_cast<int64_t>(parsed.header.flags);
  request["source"] = source;

  JsonArray inputs;
  const bool has_prevout_scripts = HasFlag(parsed.header.flags, kFlagPrevoutScriptPubkeys);
  const bool has_script_sigs = HasFlag(parsed.header.flags, kFlagScriptSigs);
  const bool has_txinwitnesses = HasFlag(parsed.header.flags, kFlagTxinWitnesses);
  const bool has_private_keys = HasFlag(parsed.header.flags, kFlagInputPrivateKeys);
  const bool has_public_keys = HasFlag(parsed.header.flags, kFlagInputPublicKeys);

  for (const InputEntryV2& entry : parsed.inputs) {
    JsonObject input;
    input["outpoint_txid"] = HexEncodeReversed(entry.outpoint_txid);
    input["outpoint_vout"] = static_cast<int64_t>(entry.outpoint_vout);
    switch (entry.input_type) {
      case 0x01:
        input["input_type"] = "p2wpkh";
        break;
      case 0x02:
        input["input_type"] = "p2tr";
        break;
      case 0x03:
        input["input_type"] = "p2sh-p2wpkh";
        break;
      case 0x04:
        input["input_type"] = "p2pkh";
        break;
      default:
        throw SemanticBridgeError("invalid input_type");
    }

    if (has_prevout_scripts) {
      if (entry.prevout_script_pubkey.empty()) {
        throw SemanticBridgeError("invalid prevout_script_pubkey");
      }
      input["prevout_script_pubkey"] = HexEncode(entry.prevout_script_pubkey);
    } else {
      input["prevout_script_pubkey"] = nullptr;
    }

    if (has_script_sigs) {
      input["script_sig"] = HexEncode(entry.script_sig);
    } else {
      input["script_sig"] = nullptr;
    }

    if (has_txinwitnesses) {
      input["txinwitness"] = HexEncode(entry.txinwitness);
      input["txinwitness_stack"] = DecodeTxInWitnessStack(entry.txinwitness);
    } else {
      input["txinwitness"] = nullptr;
      input["txinwitness_stack"] = JsonArray{};
    }

    if (has_private_keys) {
      if (entry.privkey.size() != 32) {
        throw SemanticBridgeError("invalid privkey");
      }
      input["privkey"] = HexEncode(entry.privkey);
    } else {
      input["privkey"] = nullptr;
    }

    if (has_public_keys) {
      if (entry.pubkey.size() != 33) {
        throw SemanticBridgeError("invalid pubkey");
      }
      input["pubkey"] = HexEncode(entry.pubkey);
    } else {
      input["pubkey"] = nullptr;
    }

    inputs.emplace_back(std::move(input));
  }
  request["inputs"] = std::move(inputs);

  if (request_kind == "send") {
    if (!HasFlag(parsed.header.flags, kFlagRecipientGroups) || parsed.recipient_groups.empty()) {
      throw SemanticBridgeError("recipient_groups must not be empty");
    }
    JsonArray groups;
    for (const RecipientGroupV2& group : parsed.recipient_groups) {
      JsonObject value;
      value["scan_pubkey"] = HexEncode(group.scan_pubkey);
      value["spend_pubkey"] = HexEncode(group.spend_pubkey);
      value["count"] = static_cast<int64_t>(group.count);
      groups.emplace_back(std::move(value));
    }
    request["recipient_groups"] = std::move(groups);
  } else {
    if (!HasFlag(parsed.header.flags, kFlagReceiverKeyMaterial) ||
        parsed.receiver_keys.scan_privkey.size() != 32 ||
        parsed.receiver_keys.spend_privkey.size() != 32) {
      throw SemanticBridgeError("invalid receiver scan_privkey");
    }
    JsonArray outputs_to_scan;
    for (const auto& output : parsed.outputs_to_scan) {
      if (output.size() != 32) {
        throw SemanticBridgeError("invalid outputs_to_scan entry");
      }
      outputs_to_scan.emplace_back(HexEncode(output));
    }
    request["outputs_to_scan"] = std::move(outputs_to_scan);

    JsonObject receiver_keys;
    receiver_keys["scan_privkey"] = HexEncode(parsed.receiver_keys.scan_privkey);
    receiver_keys["spend_privkey"] = HexEncode(parsed.receiver_keys.spend_privkey);
    request["receiver_keys"] = std::move(receiver_keys);

    JsonArray labels;
    for (uint32_t label : parsed.labels) {
      labels.emplace_back(static_cast<int64_t>(label));
    }
    request["labels"] = std::move(labels);

    if (has_expectation_hints) {
      JsonObject hints;
      hints["detailed_outputs_required"] = detailed_outputs_required;
      request["expectation_hints"] = std::move(hints);
    }
  }

  return request;
}

}  // namespace

std::string DetectRepoRoot(const char* argv0) {
  std::error_code error;
  const std::filesystem::path current = std::filesystem::current_path(error);
  if (!error && std::filesystem::exists(current / "tests")) {
    return current.string();
  }
  if (argv0 != nullptr && argv0[0] != '\0') {
    const std::filesystem::path executable = std::filesystem::absolute(argv0, error);
    if (!error) {
      const std::filesystem::path candidate = executable.parent_path().parent_path();
      if (std::filesystem::exists(candidate / "tests")) {
        return candidate.string();
      }
    }
  }
  return current.string();
}

std::string DefaultExpectationPath(const std::string& case_path) {
  return std::filesystem::path(case_path).replace_extension(".expected.json").string();
}

uint32_t SemanticAdapterRequestVersion() {
  return static_cast<uint32_t>(kSemanticAdapterRequestVersion);
}

uint32_t SemanticContractVersion() {
  return static_cast<uint32_t>(kSemanticContractVersion);
}

bool BuildSemanticRequest(const std::string& repo_root, const std::string& case_path,
                          const SemanticRequestOptions& options,
                          std::vector<uint8_t>* request_json, std::string* error) {
  (void)repo_root;
  try {
    std::vector<uint8_t> payload;
    if (!ReadCasePayload(case_path, &payload, error)) {
      return false;
    }
    CaseV2 parsed;
    std::string parse_error;
    if (!ParseCaseV2(payload, &parsed, &parse_error)) {
      if (error) {
        *error = std::filesystem::path(case_path).string() + " is not a v2 case";
      }
      return false;
    }
    const JsonObject request = BuildRequestObject(std::filesystem::path(case_path), parsed, options);
    if (request_json != nullptr) {
      *request_json = ToBytes(SerializeJson(JsonValue(request)));
    }
    return true;
  } catch (const std::exception& exception) {
    if (error) {
      *error = exception.what();
    }
    return false;
  }
}

bool DeriveNativeSemanticResult(const std::string& repo_root,
                                const std::string& case_path,
                                const std::string& expected_path,
                                const NativeSemanticOptions& options,
                                std::vector<uint8_t>* canonical_json,
                                std::string* error) {
  (void)repo_root;
  try {
    std::vector<uint8_t> payload;
    if (!ReadCasePayload(case_path, &payload, error)) {
      return false;
    }

    CaseV2 parsed;
    std::string parse_error;
    if (!ParseCaseV2(payload, &parsed, &parse_error)) {
      if (error != nullptr) {
        *error = std::filesystem::path(case_path).string() + " is not a v2 case";
      }
      return false;
    }

    std::string resolved_expectation = expected_path;
    if (resolved_expectation.empty()) {
      resolved_expectation = DefaultExpectationPath(case_path);
    }

    std::string request_kind;
    bool detailed_outputs_available = true;
    JsonObject source;
    if (!resolved_expectation.empty() && std::filesystem::exists(resolved_expectation)) {
      const JsonValue expected_value = ValidateSemanticResultValue(ParseJsonFile(resolved_expectation));
      const JsonObject& expected = expected_value.as_object();
      request_kind = expected.at("kind").as_string();
      if (request_kind == "receive") {
        detailed_outputs_available = expected.at("detailed_outputs_available").as_bool();
      }
      source = expected.at("source").as_object();
    } else {
      request_kind = InferKind(parsed);
      source = BuildSourceFromCaseStem(std::filesystem::path(case_path), request_kind);
    }

    JsonObject native_result;
    if (request_kind == "send") {
      native_result = DeriveNativeSendSemanticResultObject(parsed, source);
    } else if (request_kind == "receive") {
      native_result = DeriveNativeReceiveSemanticResultObject(
          parsed, source, detailed_outputs_available, options);
    } else {
      throw SemanticBridgeError("unknown native semantic kind");
    }

    const JsonValue canonical =
        ValidateSemanticResultValue(JsonValue(std::move(native_result)));
    if (canonical_json != nullptr) {
      *canonical_json = ToBytes(SerializeJson(canonical));
    }
    return true;
  } catch (const std::exception& exception) {
    if (error != nullptr) {
      *error = exception.what();
    }
    return false;
  }
}

bool RunNativeScanBenchmark(const NativeScanBenchmarkOptions& options,
                            NativeScanBenchmarkReport* report, std::string* error) {
  if (report == nullptr) {
    if (error != nullptr) {
      *error = "benchmark report output is null";
    }
    return false;
  }
  if (!IsKnownNetwork(options.network)) {
    if (error != nullptr) {
      *error = "unknown network";
    }
    return false;
  }
  if (options.block_count == 0 || options.transactions_per_block == 0) {
    if (error != nullptr) {
      *error = "benchmark dimensions must be non-zero";
    }
    return false;
  }
  try {
    const std::vector<BenchmarkDensityProfile> profiles =
        ResolveBenchmarkProfiles(options.density);
    const SecpContextPtr secp = CreateSecpContext();
    uint64_t state = options.seed;
    const std::array<unsigned char, 32> scan_privkey =
        RandomValidScalar(secp.get(), &state);
    const std::array<unsigned char, 32> spend_privkey =
        RandomValidScalar(secp.get(), &state);

    NativeScanBenchmarkReport built;
    built.network = options.network;
    built.silent_payment_version = options.silent_payment_version;
    built.seed = options.seed;
    built.block_count = options.block_count;
    built.transactions_per_block = options.transactions_per_block;

    const uint64_t transaction_count =
        static_cast<uint64_t>(options.block_count) * options.transactions_per_block;
    const uint32_t thread_count =
        ResolveBenchmarkThreadCount(options.thread_count, transaction_count);
    built.thread_count = thread_count;

    for (const BenchmarkDensityProfile& profile : profiles) {
      std::vector<CaseV2> cases;
      cases.reserve(static_cast<size_t>(transaction_count));
      for (uint64_t index = 0; index < transaction_count; ++index) {
        cases.push_back(BuildSyntheticReceiveBenchmarkCase(
            secp.get(), scan_privkey, spend_privkey, profile.outputs_per_transaction, index,
            &state));
      }

      std::vector<uint64_t> matched_transactions(thread_count, 0);
      std::vector<uint64_t> found_outputs(thread_count, 0);
      std::vector<std::string> thread_errors(thread_count);
      std::vector<std::thread> threads;
      threads.reserve(thread_count);

      const size_t chunk_size =
          (cases.size() + static_cast<size_t>(thread_count) - 1) / thread_count;
      const auto started = std::chrono::steady_clock::now();
      for (uint32_t worker = 0; worker < thread_count; ++worker) {
        const size_t begin = static_cast<size_t>(worker) * chunk_size;
        if (begin >= cases.size()) {
          break;
        }
        const size_t end = std::min(cases.size(), begin + chunk_size);
        threads.emplace_back([&, worker, begin, end]() {
          RunSyntheticReceiveBenchmarkRange(cases, begin, end, &matched_transactions[worker],
                                           &found_outputs[worker], &thread_errors[worker]);
        });
      }
      for (std::thread& thread : threads) {
        thread.join();
      }
      const auto finished = std::chrono::steady_clock::now();

      for (const std::string& thread_error : thread_errors) {
        if (!thread_error.empty()) {
          throw SemanticBridgeError(thread_error);
        }
      }

      NativeScanBenchmarkProfile result;
      result.density = profile.name;
      result.outputs_per_transaction = profile.outputs_per_transaction;
      result.block_count = options.block_count;
      result.transaction_count = transaction_count;
      result.output_count = transaction_count * profile.outputs_per_transaction;
      result.elapsed_nanoseconds = static_cast<uint64_t>(
          std::chrono::duration_cast<std::chrono::nanoseconds>(finished - started).count());
      for (uint64_t value : matched_transactions) {
        result.matched_transaction_count += value;
      }
      for (uint64_t value : found_outputs) {
        result.found_output_count += value;
      }
      built.profiles.push_back(std::move(result));
    }

    *report = std::move(built);
    return true;
  } catch (const std::exception& exception) {
    if (error != nullptr) {
      *error = exception.what();
    }
    return false;
  }
}

bool ExportDescriptorWallet(const std::string& network,
                            uint32_t silent_payment_version,
                            const std::string& scan_secret_key_hex,
                            const std::string& spend_secret_key_hex,
                            DescriptorWalletExport* export_data, std::string* error) {
  if (export_data == nullptr) {
    if (error != nullptr) {
      *error = "wallet export output is null";
    }
    return false;
  }
  if (!IsKnownNetwork(network)) {
    if (error != nullptr) {
      *error = "unknown network";
    }
    return false;
  }
  try {
    const SecpContextPtr secp = CreateSecpContext();
    const std::array<unsigned char, 32> scan_privkey = HexToArray32(scan_secret_key_hex);
    const std::array<unsigned char, 32> spend_privkey = HexToArray32(spend_secret_key_hex);
    if (!VerifyScalar(secp.get(), scan_privkey) || !VerifyScalar(secp.get(), spend_privkey)) {
      throw SemanticBridgeError("wallet export keys must be valid secp256k1 scalars");
    }

    secp256k1_pubkey scan_pubkey;
    secp256k1_pubkey spend_pubkey;
    if (!CreatePubkeyFromScalar(secp.get(), scan_privkey, &scan_pubkey) ||
        !CreatePubkeyFromScalar(secp.get(), spend_privkey, &spend_pubkey)) {
      throw SemanticBridgeError("unable to derive wallet export pubkeys");
    }

    std::array<unsigned char, 33> scan_encoded{};
    std::array<unsigned char, 33> spend_encoded{};
    if (!SerializeCompressedPubkey(secp.get(), scan_pubkey, &scan_encoded) ||
        !SerializeCompressedPubkey(secp.get(), spend_pubkey, &spend_encoded)) {
      throw SemanticBridgeError("unable to serialize wallet export pubkeys");
    }

    DescriptorWalletExport built;
    built.network = network;
    built.silent_payment_version = silent_payment_version;
    built.scan_secret_key_hex = scan_secret_key_hex;
    built.spend_secret_key_hex = spend_secret_key_hex;
    built.scan_secret_key_wif = EncodeWif(scan_privkey, network);
    built.spend_secret_key_wif = EncodeWif(spend_privkey, network);
    built.scan_key_expression = built.scan_secret_key_wif;
    built.taproot_descriptor =
        WithDescriptorChecksum("tr(" + built.spend_secret_key_wif + ")");
    built.silent_payment_address =
        EncodeSilentPaymentAddress(scan_encoded, spend_encoded, network, silent_payment_version);
    built.warning =
        "Descriptor wallets can import the spend key descriptor directly. The scan key is "
        "exported as a descriptor-compatible WIF key expression, but Silent Payments still "
        "requires wallet software that understands the separate scan secret.";
    *export_data = std::move(built);
    return true;
  } catch (const std::exception& exception) {
    if (error != nullptr) {
      *error = exception.what();
    }
    return false;
  }
}

bool DeriveNativeSendSemanticResult(const std::string& repo_root,
                                    const std::string& case_path,
                                    const std::string& expected_path,
                                    std::vector<uint8_t>* canonical_json,
                                    std::string* error) {
  NativeSemanticOptions options;
  return DeriveNativeSemanticResult(repo_root, case_path, expected_path, options,
                                    canonical_json, error);
}

}  // namespace sp_differ
