// SPDX-License-Identifier: MIT
#include "../../ffi/sp_differ.h"
#include "../../src/core/case.h"

#include <secp256k1.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

void prepare_input_key(const secp256k1_context* ctx, unsigned char key[32],
                       uint8_t input_type);

namespace {

constexpr uint8_t kInputTypeP2WPKH = 0x01;
constexpr uint8_t kInputTypeP2TRKeypath = 0x02;
constexpr uint8_t kInputTypeP2SHP2WPKH = 0x03;

using Scalar = std::array<unsigned char, 32>;
using CompressedPubkey = std::array<unsigned char, 33>;
using OutputRecord = std::pair<CompressedPubkey, Scalar>;

struct SecpContextDeleter {
  void operator()(secp256k1_context* context) const {
    if (context != nullptr) {
      secp256k1_context_destroy(context);
    }
  }
};

using SecpContextPtr = std::unique_ptr<secp256k1_context, SecpContextDeleter>;

bool IsSupportedInputType(uint8_t input_type) {
  return input_type == kInputTypeP2WPKH || input_type == kInputTypeP2TRKeypath ||
         input_type == kInputTypeP2SHP2WPKH;
}

bool CreateContext(SecpContextPtr* out) {
  SecpContextPtr context(
      secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY));
  if (!context) {
    return false;
  }
  *out = std::move(context);
  return true;
}

bool SerializeCompressed(const secp256k1_context* ctx, const secp256k1_pubkey& pubkey,
                        CompressedPubkey* out) {
  size_t size = out->size();
  return secp256k1_ec_pubkey_serialize(ctx, out->data(), &size, &pubkey,
                                       SECP256K1_EC_COMPRESSED) == 1 &&
         size == out->size();
}

bool ParseCompressed(const secp256k1_context* ctx, const std::vector<uint8_t>& bytes,
                     secp256k1_pubkey* out) {
  return bytes.size() == 33 &&
         secp256k1_ec_pubkey_parse(ctx, out, bytes.data(), bytes.size()) == 1;
}

bool CreatePubkey(const secp256k1_context* ctx, const Scalar& seckey,
                  secp256k1_pubkey* out) {
  return secp256k1_ec_pubkey_create(ctx, out, seckey.data()) == 1;
}

// BIP352 sender logic uses the negated Taproot secret when the full pubkey
// has odd Y so the x-only key is interpreted with even-Y parity.
bool SerializeInputPubkey(const secp256k1_context* ctx, const Scalar& seckey,
                         uint8_t input_type, CompressedPubkey* out) {
  Scalar normalized = seckey;
  if (input_type == kInputTypeP2TRKeypath) {
    secp256k1_pubkey pubkey;
    if (!CreatePubkey(ctx, normalized, &pubkey)) {
      return false;
    }
    CompressedPubkey serialized{};
    if (!SerializeCompressed(ctx, pubkey, &serialized)) {
      return false;
    }
    if (serialized[0] == 0x03 &&
        secp256k1_ec_seckey_negate(ctx, normalized.data()) != 1) {
      return false;
    }
  }

  secp256k1_pubkey normalized_pubkey;
  return CreatePubkey(ctx, normalized, &normalized_pubkey) &&
         SerializeCompressed(ctx, normalized_pubkey, out);
}

bool ValidateOptionalInputPubkey(const secp256k1_context* ctx,
                                 const sp_differ::InputEntry& entry,
                                 const Scalar& seckey) {
  if (entry.pubkey.empty()) {
    return true;
  }
  CompressedPubkey derived{};
  if (!SerializeInputPubkey(ctx, seckey, entry.input_type, &derived)) {
    return false;
  }
  return std::equal(derived.begin(), derived.end(), entry.pubkey.begin(), entry.pubkey.end());
}

bool PrepareInputScalar(const secp256k1_context* ctx, const sp_differ::InputEntry& entry,
                        Scalar* normalized, sp_differ_status* status) {
  if (entry.privkey.size() != 32 || !IsSupportedInputType(entry.input_type)) {
    *status = SP_DIFFER_STATUS_INVALID_INPUT;
    return false;
  }

  std::memcpy(normalized->data(), entry.privkey.data(), normalized->size());
  if (secp256k1_ec_seckey_verify(ctx, normalized->data()) != 1) {
    *status = SP_DIFFER_STATUS_INVALID_INPUT;
    return false;
  }

  if (!ValidateOptionalInputPubkey(ctx, entry, *normalized)) {
    *status = SP_DIFFER_STATUS_INVALID_INPUT;
    return false;
  }

  ::prepare_input_key(ctx, normalized->data(), entry.input_type);
  if (secp256k1_ec_seckey_verify(ctx, normalized->data()) != 1) {
    *status = SP_DIFFER_STATUS_INVALID_INPUT;
    return false;
  }
  return true;
}

// BIP352 hashes the lexicographically smallest serialized outpoint, not the
// first input in transaction order.
bool BuildSmallestOutpoint(const std::vector<sp_differ::InputEntry>& inputs,
                           std::array<unsigned char, 36>* outpoint) {
  if (inputs.empty()) {
    return false;
  }

  bool have_smallest = false;
  std::array<unsigned char, 36> candidate{};
  for (const auto& entry : inputs) {
    if (entry.outpoint_txid.size() != 32) {
      return false;
    }
    std::array<unsigned char, 36> current{};
    std::memcpy(current.data(), entry.outpoint_txid.data(), 32);
    current[32] = static_cast<unsigned char>(entry.outpoint_vout & 0xFF);
    current[33] = static_cast<unsigned char>((entry.outpoint_vout >> 8) & 0xFF);
    current[34] = static_cast<unsigned char>((entry.outpoint_vout >> 16) & 0xFF);
    current[35] = static_cast<unsigned char>((entry.outpoint_vout >> 24) & 0xFF);
    if (!have_smallest || current < candidate) {
      candidate = current;
      have_smallest = true;
    }
  }

  if (!have_smallest) {
    return false;
  }
  *outpoint = candidate;
  return true;
}

bool TaggedHash(const secp256k1_context* ctx, const std::string& tag,
                const std::vector<unsigned char>& message, Scalar* out) {
  return secp256k1_tagged_sha256(ctx, out->data(),
                                 reinterpret_cast<const unsigned char*>(tag.data()),
                                 tag.size(), message.data(), message.size()) == 1;
}

bool SumInputSecretKeys(const secp256k1_context* ctx,
                        const std::vector<sp_differ::InputEntry>& inputs,
                        Scalar* sum, sp_differ_status* status) {
  bool have_any = false;
  for (const auto& entry : inputs) {
    Scalar normalized{};
    if (!PrepareInputScalar(ctx, entry, &normalized, status)) {
      return false;
    }
    if (!have_any) {
      *sum = normalized;
      have_any = true;
      continue;
    }
    if (secp256k1_ec_seckey_tweak_add(ctx, sum->data(), normalized.data()) != 1) {
      *status = SP_DIFFER_STATUS_ZERO_SCALAR;
      return false;
    }
  }

  if (!have_any) {
    *status = SP_DIFFER_STATUS_INVALID_INPUT;
    return false;
  }
  return true;
}

bool ComputeInputHash(const secp256k1_context* ctx, const sp_differ::Case& parsed,
                      const Scalar& input_private_key_sum, Scalar* input_hash,
                      sp_differ_status* status) {
  secp256k1_pubkey sum_pubkey;
  if (!CreatePubkey(ctx, input_private_key_sum, &sum_pubkey)) {
    *status = SP_DIFFER_STATUS_ZERO_SCALAR;
    return false;
  }

  CompressedPubkey serialized_sum{};
  if (!SerializeCompressed(ctx, sum_pubkey, &serialized_sum)) {
    *status = SP_DIFFER_STATUS_INTERNAL;
    return false;
  }

  std::array<unsigned char, 36> smallest_outpoint{};
  if (!BuildSmallestOutpoint(parsed.inputs, &smallest_outpoint)) {
    *status = SP_DIFFER_STATUS_INVALID_INPUT;
    return false;
  }

  std::vector<unsigned char> message;
  message.reserve(smallest_outpoint.size() + serialized_sum.size());
  message.insert(message.end(), smallest_outpoint.begin(), smallest_outpoint.end());
  message.insert(message.end(), serialized_sum.begin(), serialized_sum.end());
  // input_hash = tagged_hash("BIP0352/Inputs", outpoint_L || A), where
  // A = a*G for the sum of normalized sender input keys.
  if (!TaggedHash(ctx, "BIP0352/Inputs", message, input_hash)) {
    *status = SP_DIFFER_STATUS_INTERNAL;
    return false;
  }
  if (secp256k1_ec_seckey_verify(ctx, input_hash->data()) != 1) {
    *status = SP_DIFFER_STATUS_TWEAK_OUT_OF_RANGE;
    return false;
  }
  return true;
}

// shared_secret = input_hash * a_sum * B_scan. The multiplication order does
// not change the group result, but the status mapping distinguishes internal
// failures from an out-of-range input_hash-derived tweak.
bool ComputeSharedSecret(const secp256k1_context* ctx, const sp_differ::Case& parsed,
                         const Scalar& input_private_key_sum, const Scalar& input_hash,
                         secp256k1_pubkey* out, sp_differ_status* status) {
  if (!ParseCompressed(ctx, parsed.scan_pubkey, out)) {
    *status = SP_DIFFER_STATUS_INVALID_PUBKEY;
    return false;
  }
  if (secp256k1_ec_pubkey_tweak_mul(ctx, out, input_private_key_sum.data()) != 1) {
    *status = SP_DIFFER_STATUS_INTERNAL;
    return false;
  }
  if (secp256k1_ec_pubkey_tweak_mul(ctx, out, input_hash.data()) != 1) {
    *status = SP_DIFFER_STATUS_TWEAK_OUT_OF_RANGE;
    return false;
  }
  return true;
}

bool BuildOutputRecords(const secp256k1_context* ctx, const sp_differ::Case& parsed,
                        std::vector<OutputRecord>* outputs, sp_differ_status* status) {
  // The v1 byte-worker path does not implement label-derived outputs. Labels
  // are handled in the v2 semantic path instead.
  if (!parsed.labels.empty()) {
    *status = SP_DIFFER_STATUS_INVALID_INPUT;
    return false;
  }

  if (parsed.header.output_count == 0) {
    outputs->clear();
    return true;
  }

  Scalar input_private_key_sum{};
  if (!SumInputSecretKeys(ctx, parsed.inputs, &input_private_key_sum, status)) {
    return false;
  }

  Scalar input_hash{};
  if (!ComputeInputHash(ctx, parsed, input_private_key_sum, &input_hash, status)) {
    return false;
  }

  secp256k1_pubkey shared_secret;
  if (!ComputeSharedSecret(ctx, parsed, input_private_key_sum, input_hash, &shared_secret,
                           status)) {
    return false;
  }

  secp256k1_pubkey spend_pubkey;
  if (!ParseCompressed(ctx, parsed.spend_pubkey, &spend_pubkey)) {
    *status = SP_DIFFER_STATUS_INVALID_PUBKEY;
    return false;
  }

  CompressedPubkey shared_secret_bytes{};
  if (!SerializeCompressed(ctx, shared_secret, &shared_secret_bytes)) {
    *status = SP_DIFFER_STATUS_INTERNAL;
    return false;
  }

  outputs->clear();
  outputs->reserve(parsed.header.output_count);
  // Each recipient index uses ser32(index) in big-endian order:
  // tweak_n = tagged_hash("BIP0352/SharedSecret", shared_secret || ser32(n)).
  for (uint32_t index = 0; index < parsed.header.output_count; ++index) {
    std::vector<unsigned char> message;
    message.reserve(shared_secret_bytes.size() + 4);
    message.insert(message.end(), shared_secret_bytes.begin(), shared_secret_bytes.end());
    message.push_back(static_cast<unsigned char>((index >> 24) & 0xFF));
    message.push_back(static_cast<unsigned char>((index >> 16) & 0xFF));
    message.push_back(static_cast<unsigned char>((index >> 8) & 0xFF));
    message.push_back(static_cast<unsigned char>(index & 0xFF));

    Scalar tweak{};
    if (!TaggedHash(ctx, "BIP0352/SharedSecret", message, &tweak)) {
      *status = SP_DIFFER_STATUS_INTERNAL;
      return false;
    }
    if (secp256k1_ec_seckey_verify(ctx, tweak.data()) != 1) {
      *status = SP_DIFFER_STATUS_TWEAK_OUT_OF_RANGE;
      return false;
    }

    secp256k1_pubkey output_pubkey = spend_pubkey;
    if (secp256k1_ec_pubkey_tweak_add(ctx, &output_pubkey, tweak.data()) != 1) {
      *status = SP_DIFFER_STATUS_TWEAK_OUT_OF_RANGE;
      return false;
    }

    CompressedPubkey serialized_output{};
    if (!SerializeCompressed(ctx, output_pubkey, &serialized_output)) {
      *status = SP_DIFFER_STATUS_INTERNAL;
      return false;
    }
    outputs->push_back(OutputRecord(serialized_output, tweak));
  }

  return true;
}

std::vector<uint8_t> SerializeOutputPayload(sp_differ_status status,
                                            const std::vector<OutputRecord>& outputs) {
  const uint16_t output_count =
      status == SP_DIFFER_STATUS_OK ? static_cast<uint16_t>(outputs.size()) : 0u;
  std::vector<uint8_t> payload;
  payload.reserve(4 + output_count * (33 + 32));
  payload.push_back(1);
  payload.push_back(static_cast<uint8_t>(status));
  payload.push_back(static_cast<uint8_t>(output_count & 0xFF));
  payload.push_back(static_cast<uint8_t>((output_count >> 8) & 0xFF));

  if (status != SP_DIFFER_STATUS_OK) {
    return payload;
  }

  for (const auto& output : outputs) {
    payload.insert(payload.end(), output.first.begin(), output.first.end());
  }
  for (const auto& output : outputs) {
    payload.insert(payload.end(), output.second.begin(), output.second.end());
  }
  return payload;
}

int RunCaseV1(const uint8_t* input, size_t input_len, std::vector<uint8_t>* output) {
  if (input == nullptr || output == nullptr || input_len == 0) {
    return -1;
  }

  std::vector<uint8_t> payload(input, input + input_len);
  sp_differ::Case parsed;
  std::string error;
  if (!sp_differ::ParseCaseV1(payload, &parsed, &error)) {
    *output = SerializeOutputPayload(SP_DIFFER_STATUS_INVALID_INPUT, {});
    return 0;
  }

  SecpContextPtr ctx;
  if (!CreateContext(&ctx)) {
    return -1;
  }

  sp_differ_status status = SP_DIFFER_STATUS_OK;
  std::vector<OutputRecord> records;
  if (!BuildOutputRecords(ctx.get(), parsed, &records, &status)) {
    *output = SerializeOutputPayload(status, {});
    return 0;
  }

  *output = SerializeOutputPayload(SP_DIFFER_STATUS_OK, records);
  return 0;
}

}  // namespace

void prepare_input_key(const secp256k1_context* ctx, unsigned char key[32],
                       uint8_t input_type) {
  if (ctx == nullptr || key == nullptr || input_type != kInputTypeP2TRKeypath) {
    return;
  }

  secp256k1_pubkey pubkey;
  if (secp256k1_ec_pubkey_create(ctx, &pubkey, key) != 1) {
    return;
  }

  CompressedPubkey serialized{};
  if (!SerializeCompressed(ctx, pubkey, &serialized)) {
    return;
  }

  if (serialized[0] == 0x03) {
    if (secp256k1_ec_seckey_negate(ctx, key) != 1) {
      std::memset(key, 0, 32);
    }
  }
}

extern "C" uint32_t sp_differ_worker_api_version(void) {
  return SP_DIFFER_WORKER_API_VERSION;
}

extern "C" int sp_differ_worker_run(const uint8_t* input, size_t input_len, uint8_t** output,
                                    size_t* output_len) {
  if (output == nullptr || output_len == nullptr) {
    return -1;
  }

  std::vector<uint8_t> payload;
  if (RunCaseV1(input, input_len, &payload) != 0) {
    return -1;
  }

  const size_t size = payload.empty() ? 1 : payload.size();
  uint8_t* buffer = static_cast<uint8_t*>(std::malloc(size));
  if (buffer == nullptr) {
    return -1;
  }
  if (!payload.empty()) {
    std::memcpy(buffer, payload.data(), payload.size());
  }
  *output = buffer;
  *output_len = payload.size();
  return 0;
}

extern "C" void sp_differ_worker_free(uint8_t* output) {
  std::free(output);
}
