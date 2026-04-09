// SPDX-License-Identifier: MIT
#include "semantic_encoding.hpp"

#include "semantic_json.hpp"

#include <openssl/bn.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace sp_differ {
namespace {

const char* kBech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
constexpr std::array<uint32_t, 5> kBech32Generators = {
    0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3,
};
constexpr uint32_t kBech32mConst = 0x2bc830a3;

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

uint32_t Bech32Polymod(const std::vector<uint8_t>& values) {
  uint32_t chk = 1;
  for (uint8_t value : values) {
    const uint8_t top = static_cast<uint8_t>(chk >> 25);
    chk = ((chk & 0x1ffffff) << 5) ^ value;
    for (size_t i = 0; i < kBech32Generators.size(); ++i) {
      if ((top >> i) & 1U) {
        chk ^= kBech32Generators[i];
      }
    }
  }
  return chk;
}

std::vector<uint8_t> Bech32HrpExpand(const std::string& hrp) {
  std::vector<uint8_t> expanded;
  expanded.reserve(hrp.size() * 2 + 1);
  for (char ch : hrp) {
    expanded.push_back(static_cast<uint8_t>(static_cast<unsigned char>(ch) >> 5));
  }
  expanded.push_back(0);
  for (char ch : hrp) {
    expanded.push_back(static_cast<uint8_t>(static_cast<unsigned char>(ch) & 31));
  }
  return expanded;
}

std::vector<uint8_t> Bech32CreateChecksum(const std::string& hrp,
                                          const std::vector<uint8_t>& data) {
  std::vector<uint8_t> values = Bech32HrpExpand(hrp);
  values.insert(values.end(), data.begin(), data.end());
  values.insert(values.end(), 6, 0);
  const uint32_t polymod = Bech32Polymod(values) ^ kBech32mConst;
  std::vector<uint8_t> checksum(6);
  for (size_t i = 0; i < checksum.size(); ++i) {
    checksum[i] = static_cast<uint8_t>((polymod >> (5 * (5 - i))) & 31);
  }
  return checksum;
}

bool ConvertBits(const std::vector<unsigned char>& input, int from_bits,
                 int to_bits, bool pad, std::vector<uint8_t>* output) {
  int acc = 0;
  int bits = 0;
  const int maxv = (1 << to_bits) - 1;
  const int max_acc = (1 << (from_bits + to_bits - 1)) - 1;
  for (unsigned char value : input) {
    if ((value >> from_bits) != 0) {
      return false;
    }
    acc = ((acc << from_bits) | value) & max_acc;
    bits += from_bits;
    while (bits >= to_bits) {
      bits -= to_bits;
      output->push_back(static_cast<uint8_t>((acc >> bits) & maxv));
    }
  }
  if (pad) {
    if (bits != 0) {
      output->push_back(
          static_cast<uint8_t>((acc << (to_bits - bits)) & maxv));
    }
  } else if (bits >= from_bits ||
             ((acc << (to_bits - bits)) & maxv) != 0) {
    return false;
  }
  return true;
}

std::string Bech32Encode(const std::string& hrp,
                         const std::vector<uint8_t>& data) {
  std::vector<uint8_t> combined = data;
  const std::vector<uint8_t> checksum = Bech32CreateChecksum(hrp, data);
  combined.insert(combined.end(), checksum.begin(), checksum.end());
  std::string out = hrp;
  out.push_back('1');
  for (uint8_t value : combined) {
    if (value >= 32) {
      throw SemanticBridgeError("invalid bech32 value");
    }
    out.push_back(kBech32Charset[value]);
  }
  return out;
}

std::string NetworkHrp(const std::string& network) {
  return network == "mainnet" ? "sp" : "tsp";
}

uint8_t NetworkWifPrefix(const std::string& network) {
  return network == "mainnet" ? 0x80 : 0xEF;
}

std::array<unsigned char, 32> DoubleSha256(
    const std::vector<unsigned char>& data) {
  std::array<unsigned char, 32> first{};
  std::array<unsigned char, 32> second{};
  const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> digest(
      EVP_MD_CTX_new(), &EVP_MD_CTX_free);
  unsigned int output_len = 0;
  if (!digest || EVP_DigestInit_ex(digest.get(), EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(digest.get(), data.data(), data.size()) != 1 ||
      EVP_DigestFinal_ex(digest.get(), first.data(), &output_len) != 1 ||
      output_len != first.size()) {
    throw SemanticBridgeError("unable to compute sha256");
  }
  if (EVP_DigestInit_ex(digest.get(), EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(digest.get(), first.data(), first.size()) != 1 ||
      EVP_DigestFinal_ex(digest.get(), second.data(), &output_len) != 1 ||
      output_len != second.size()) {
    throw SemanticBridgeError("unable to compute sha256");
  }
  return second;
}

std::string Base58Encode(const std::vector<unsigned char>& bytes) {
  static const char* kBase58Alphabet =
      "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  BnPtr value(BN_bin2bn(bytes.data(), static_cast<int>(bytes.size()), nullptr));
  BnPtr base(BN_new());
  BnPtr quotient(BN_new());
  BnPtr remainder(BN_new());
  BnCtxPtr ctx(BN_CTX_new());
  if (!value || !base || !quotient || !remainder || !ctx ||
      BN_set_word(base.get(), 58) != 1) {
    throw SemanticBridgeError("unable to initialize base58 encoder");
  }

  std::string encoded;
  while (!BN_is_zero(value.get())) {
    if (BN_div(quotient.get(), remainder.get(), value.get(), base.get(),
               ctx.get()) != 1) {
      throw SemanticBridgeError("unable to encode base58 value");
    }
    const unsigned long digit = BN_get_word(remainder.get());
    if (digit >= 58) {
      throw SemanticBridgeError("invalid base58 remainder");
    }
    encoded.push_back(kBase58Alphabet[digit]);
    if (BN_copy(value.get(), quotient.get()) == nullptr) {
      throw SemanticBridgeError("unable to update base58 quotient");
    }
  }

  for (unsigned char byte : bytes) {
    if (byte != 0) {
      break;
    }
    encoded.push_back('1');
  }
  std::reverse(encoded.begin(), encoded.end());
  return encoded.empty() ? "1" : encoded;
}

std::string Base58CheckEncode(const std::vector<unsigned char>& payload) {
  std::vector<unsigned char> bytes = payload;
  const std::array<unsigned char, 32> checksum = DoubleSha256(payload);
  bytes.insert(bytes.end(), checksum.begin(), checksum.begin() + 4);
  return Base58Encode(bytes);
}

std::string DescriptorChecksum(const std::string& descriptor) {
  static const char* kInputCharset =
      "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
      "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
  static const char* kChecksumCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  static const std::array<uint64_t, 5> kDescriptorGenerators = {
      0xf5dee51989ULL, 0xa9fdca3312ULL, 0x1bab10e32dULL, 0x3706b1677aULL,
      0x644d626ffdULL,
  };

  auto polymod = [&](const std::vector<uint8_t>& symbols) -> uint64_t {
    uint64_t chk = 1;
    for (uint8_t symbol : symbols) {
      const uint64_t top = chk >> 35;
      chk = ((chk & 0x7ffffffffULL) << 5) ^ symbol;
      for (size_t i = 0; i < kDescriptorGenerators.size(); ++i) {
        if (((top >> i) & 1U) != 0U) {
          chk ^= kDescriptorGenerators[i];
        }
      }
    }
    return chk;
  };

  std::vector<uint8_t> groups;
  std::vector<uint8_t> symbols;
  groups.reserve((descriptor.size() + 2) / 3);
  symbols.reserve(descriptor.size() + descriptor.size() / 3 + 8);
  for (char ch : descriptor) {
    const char* found = std::strchr(kInputCharset, ch);
    if (found == nullptr) {
      throw SemanticBridgeError("descriptor contains unsupported character");
    }
    const uint8_t value = static_cast<uint8_t>(found - kInputCharset);
    symbols.push_back(value & 31U);
    groups.push_back(value >> 5U);
    if (groups.size() == 3) {
      symbols.push_back(
          static_cast<uint8_t>(groups[0] * 9 + groups[1] * 3 + groups[2]));
      groups.clear();
    }
  }
  if (groups.size() == 1) {
    symbols.push_back(groups[0]);
  } else if (groups.size() == 2) {
    symbols.push_back(static_cast<uint8_t>(groups[0] * 3 + groups[1]));
  }
  symbols.insert(symbols.end(), 8, 0);
  const uint64_t checksum = polymod(symbols) ^ 1U;
  std::string out;
  out.reserve(8);
  for (int i = 0; i < 8; ++i) {
    out.push_back(kChecksumCharset[(checksum >> (5 * (7 - i))) & 31U]);
  }
  return out;
}

}  // namespace

std::string EncodeSilentPaymentAddress(
    const std::array<unsigned char, 33>& scan_pubkey,
    const std::array<unsigned char, 33>& spend_pubkey,
    const std::string& network, uint32_t silent_payment_version) {
  if (silent_payment_version > 31) {
    throw SemanticBridgeError("unsupported silent payment version");
  }
  std::vector<unsigned char> payload;
  payload.reserve(scan_pubkey.size() + spend_pubkey.size());
  payload.insert(payload.end(), scan_pubkey.begin(), scan_pubkey.end());
  payload.insert(payload.end(), spend_pubkey.begin(), spend_pubkey.end());
  std::vector<uint8_t> data;
  data.push_back(static_cast<uint8_t>(silent_payment_version));
  if (!ConvertBits(payload, 8, 5, true, &data)) {
    throw SemanticBridgeError(
        "unable to convert silent payment address payload");
  }
  return Bech32Encode(NetworkHrp(network), data);
}

std::string EncodeWif(const std::array<unsigned char, 32>& key,
                      const std::string& network) {
  std::vector<unsigned char> payload;
  payload.reserve(34);
  payload.push_back(NetworkWifPrefix(network));
  payload.insert(payload.end(), key.begin(), key.end());
  payload.push_back(0x01);
  return Base58CheckEncode(payload);
}

std::string WithDescriptorChecksum(const std::string& descriptor) {
  return descriptor + "#" + DescriptorChecksum(descriptor);
}

}  // namespace sp_differ
