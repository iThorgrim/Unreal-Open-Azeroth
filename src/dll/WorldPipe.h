#pragma once
#include <cstdint>
#include <vector>
#include <winsock2.h>
#include "WorldCipher.h"

namespace uoa::world {

// One direction of the world stream: frames packets, remaps opcodes, re-encrypts, and forwards
// to `out`. Dropped opcodes (remap returns -1) are suppressed. The first packet of each side is
// plaintext (the auth handshake) and forwarded unchanged.
class Pipe {
public:
    using Remap = int (*)(int opcode);   // opcode -> opcode, or -1 to drop

    Pipe(SOCKET out, int headerLen, Remap remap, const char* tag);
    void feed(const uint8_t* data, int len);

private:
    void parse();

    SOCKET       out_;
    int          headerLen_;
    int          bodyAdjust_;   // cmd bytes in the header: 6-byte header -> 4, 4-byte header -> 2
    Remap        remap_;
    const char*  tag_;
    bool         cryptActive_   = false;
    bool         inBody_        = false;
    bool         forwardBody_   = true;
    int          bodyRemaining_ = 0;
    HeaderCipher recv_;
    HeaderCipher send_;
    std::vector<uint8_t> buf_;
};

} // namespace uoa::world
