#pragma once
#include <cstdint>
#include <cstddef>

namespace uoa {

// Minimal streaming SHA-1, used for the realmd integrity crc_hash.
class Sha1 {
public:
    Sha1();
    void update(const uint8_t* data, size_t len);
    void finish(uint8_t out[20]);

private:
    void block(const uint8_t* p);

    uint32_t h_[5];
    uint64_t total_;
    uint8_t  buf_[64];
    uint32_t pending_;
};

} // namespace uoa
