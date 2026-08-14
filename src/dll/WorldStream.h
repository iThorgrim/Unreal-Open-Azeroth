#pragma once
#include <cstdint>
#include <vector>

namespace uoa::world {

// Reassembles one direction of the world stream and logs each packet's decrypted opcode.
// Header-only encryption: the first packet of each side is plaintext, the rest are ciphered.
class Stream {
public:
    enum Direction { ClientToServer, ServerToClient };

    Stream(Direction dir, const char* tag);
    void feed(const uint8_t* data, int len);

private:
    void parse();
    void decryptHeader(uint8_t* header, int len);

    Direction   dir_;
    const char* tag_;
    int         headerLen_;
    bool        cryptActive_   = false;
    bool        inBody_        = false;
    int         bodyRemaining_ = 0;
    uint8_t     i_ = 0;
    uint8_t     j_ = 0;
    std::vector<uint8_t> buf_;
};

} // namespace uoa::world
