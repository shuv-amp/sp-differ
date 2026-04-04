// SPDX-License-Identifier: MIT
#include "../../ffi/sp_differ.h"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <secp256k1.h>

void prepare_input_key(const secp256k1_context* ctx, unsigned char key[32],
                       uint8_t input_type);

namespace {

constexpr uint8_t kInputTypeP2TRKeypath = 0x02;
constexpr uint8_t kInputTypeP2WPKH = 0x01;
constexpr uint8_t kInputTypeP2PKH = 0x04;

std::vector<uint8_t> BuildV1Case(uint8_t input_type) {
    std::vector<uint8_t> payload;
    payload.push_back(1);  // version

    for (int i = 0; i < 8; ++i) {
        payload.push_back(0);  // seed
    }

    payload.push_back(1u << 1);  // flags: private keys present
    payload.push_back(0);
    payload.push_back(0);
    payload.push_back(0);

    payload.push_back(1);  // input_count
    payload.push_back(0);
    payload.push_back(1);  // output_count
    payload.push_back(0);

    payload.insert(payload.end(), 32, 0);  // outpoint txid
    payload.push_back(0);                   // vout
    payload.push_back(0);
    payload.push_back(0);
    payload.push_back(0);
    payload.push_back(input_type);

    payload.insert(payload.end(), 31, 0);
    payload.push_back(1);  // valid private key scalar = 1

    payload.push_back(0x02);
    payload.insert(payload.end(), 32, 0);  // scan pubkey
    payload.push_back(0x02);
    payload.insert(payload.end(), 32, 0);  // spend pubkey

    payload.push_back(0);  // label_count
    payload.push_back(0);

    return payload;
}

}  // namespace

// P2TR odd-Y keys are negated so the resulting public key has even Y.
void test_p2tr_odd_y_negated() {
    secp256k1_context* ctx =
        secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char key[32] = {0};
    bool found = false;
    for (int i = 2; i < 1000; i++) {
        std::memset(key, 0, sizeof(key));
        key[31] = static_cast<unsigned char>(i);
        secp256k1_pubkey pk;
        if (!secp256k1_ec_pubkey_create(ctx, &pk, key)) {
            continue;
        }
        unsigned char compressed[33];
        size_t len = sizeof(compressed);
        secp256k1_ec_pubkey_serialize(ctx, compressed, &len, &pk, SECP256K1_EC_COMPRESSED);
        if (compressed[0] == 0x03) {
            found = true;
            break;
        }
    }
    assert(found && "Must find odd-Y key in first 1000 scalars");

    prepare_input_key(ctx, key, kInputTypeP2TRKeypath);

    secp256k1_pubkey pk_after;
    int create_ok = secp256k1_ec_pubkey_create(ctx, &pk_after, key);
    assert(create_ok == 1 && "Negated key must remain a valid scalar");
    unsigned char c[33];
    size_t l = sizeof(c);
    secp256k1_ec_pubkey_serialize(ctx, c, &l, &pk_after, SECP256K1_EC_COMPRESSED);
    assert(c[0] == 0x02 && "After negation, Y must be even");

    secp256k1_context_destroy(ctx);
}

// Non-P2TR odd-Y keys are left unchanged.
void test_non_p2tr_not_negated() {
    secp256k1_context* ctx =
        secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    unsigned char key[32] = {0};
    bool found = false;
    for (int i = 2; i < 1000; i++) {
        std::memset(key, 0, sizeof(key));
        key[31] = static_cast<unsigned char>(i);
        secp256k1_pubkey pk;
        if (!secp256k1_ec_pubkey_create(ctx, &pk, key)) {
            continue;
        }
        unsigned char c[33];
        size_t l = sizeof(c);
        secp256k1_ec_pubkey_serialize(ctx, c, &l, &pk, SECP256K1_EC_COMPRESSED);
        if (c[0] == 0x03) {
            found = true;
            break;
        }
    }
    assert(found && "Must find odd-Y key in first 1000 scalars");

    unsigned char key_before[32];
    std::memcpy(key_before, key, sizeof(key));

    prepare_input_key(ctx, key, kInputTypeP2WPKH);
    assert(std::memcmp(key, key_before, sizeof(key)) == 0 &&
           "Non-P2TR keys must not be negated");

    secp256k1_context_destroy(ctx);
}

void test_v1_rejects_p2pkh_marker() {
    const std::vector<uint8_t> payload = BuildV1Case(kInputTypeP2PKH);

    uint8_t* output = nullptr;
    size_t output_len = 0;
    const int rc =
        sp_differ_worker_run(payload.data(), payload.size(), &output, &output_len);
    assert(rc == 0);
    assert(output != nullptr);
    assert(output_len == 4);
    assert(output[1] == static_cast<uint8_t>(SP_DIFFER_STATUS_INVALID_INPUT));

    sp_differ_worker_free(output);
}

int main() {
    test_p2tr_odd_y_negated();
    test_non_p2tr_not_negated();
    test_v1_rejects_p2pkh_marker();
    std::printf("All taproot negation tests passed.\n");
    return 0;
}
