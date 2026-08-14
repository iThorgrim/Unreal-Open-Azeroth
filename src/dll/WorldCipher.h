#pragma once
#include <cstdint>
#include "WorldKey.h"

namespace uoa::world {

// Per-stream AuthCrypt state (header-only). Shared 40-byte key K, independent i/j.
// decrypt is the inverse of the peer's encrypt, so a MITM re-ciphers with fresh state.
class HeaderCipher {
public:
    // p = (c - j) ^ K[i]; j = c
    void decrypt(uint8_t* buf, int len) {
        const uint8_t* key = worldkey::key();
        int keyLen = worldkey::length();
        if (!key || keyLen <= 0) return;
        for (int t = 0; t < len; ++t) {
            uint8_t cipher = buf[t];
            buf[t] = (uint8_t)((cipher - j_) ^ key[i_]);
            j_ = cipher;
            i_ = (uint8_t)((i_ + 1) % keyLen);
        }
    }

    // c = (p ^ K[i]) + j; j = c
    void encrypt(uint8_t* buf, int len) {
        const uint8_t* key = worldkey::key();
        int keyLen = worldkey::length();
        if (!key || keyLen <= 0) return;
        for (int t = 0; t < len; ++t) {
            uint8_t x = (uint8_t)((buf[t] ^ key[i_]) + j_);
            buf[t] = x;
            j_ = x;
            i_ = (uint8_t)((i_ + 1) % keyLen);
        }
    }

private:
    uint8_t i_ = 0;
    uint8_t j_ = 0;
};

} // namespace uoa::world
