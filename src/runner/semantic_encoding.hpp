#ifndef SP_DIFFER_RUNNER_SEMANTIC_ENCODING_HPP
#define SP_DIFFER_RUNNER_SEMANTIC_ENCODING_HPP

#include <array>
#include <cstdint>
#include <string>

namespace sp_differ {

std::string EncodeSilentPaymentAddress(
    const std::array<unsigned char, 33>& scan_pubkey,
    const std::array<unsigned char, 33>& spend_pubkey, const std::string& network,
    uint32_t silent_payment_version);
std::string EncodeWif(const std::array<unsigned char, 32>& key,
                      const std::string& network);
std::string WithDescriptorChecksum(const std::string& descriptor);

}  // namespace sp_differ

#endif  // SP_DIFFER_RUNNER_SEMANTIC_ENCODING_HPP
