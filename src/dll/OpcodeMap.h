#pragma once

namespace uoa::world {

// Maps a client world opcode to its mangos 1.12 equivalent.
// Returns -1 to drop the packet (client-only opcode mangos does not understand).
// Auth and ping share vanilla numbers; only the char-select flow differs so far.
inline int mapClientOpcode(int clientOpcode) {
    switch (clientOpcode) {
        case 0x060: return 0x037;   // char list request -> CMSG_CHAR_ENUM
        case 0x111: return -1;      // client keepalive -> drop
        case 0x340: return -1;      // client handshake -> drop
        default:    return clientOpcode;
    }
}

} // namespace uoa::world
