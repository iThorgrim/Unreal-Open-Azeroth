#pragma once
#include <cstdint>
#include "WorldKey.h"

namespace uoa::world {

// Per-stream vanilla-1.12 AuthCrypt state (header-only), independent i/j. The key is supplied by an
// injected source so each half of the proxy can key on a different K: the client<->proxy side keeps the
// a8 world key the client installed, while the proxy<->mangos side keys on cmangos's K. decrypt is the
// inverse of the peer's encrypt, so re-ciphering with fresh state bridges the two keyings transparently.
// A null source (key not yet captured) passes bytes through unchanged.
class HeaderCipher {
public:
    using KeyFn = const uint8_t* (*)();
    using LenFn = int (*)();

    void useKey(KeyFn k, LenFn l) { keyFn_ = k; lenFn_ = l; }

    // p = (c - j) ^ K[i]; j = c
    void decrypt(uint8_t* buf, int len) {
        const uint8_t* key = keyFn_ ? keyFn_() : worldkey::key();
        int keyLen = lenFn_ ? lenFn_() : worldkey::length();
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
        const uint8_t* key = keyFn_ ? keyFn_() : worldkey::key();
        int keyLen = lenFn_ ? lenFn_() : worldkey::length();
        if (!key || keyLen <= 0) return;
        for (int t = 0; t < len; ++t) {
            uint8_t x = (uint8_t)((buf[t] ^ key[i_]) + j_);
            buf[t] = x;
            j_ = x;
            i_ = (uint8_t)((i_ + 1) % keyLen);
        }
    }

private:
    KeyFn   keyFn_ = nullptr;
    LenFn   lenFn_ = nullptr;
    uint8_t i_ = 0;
    uint8_t j_ = 0;
};

} // namespace uoa::world
