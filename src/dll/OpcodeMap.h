#pragma once

namespace uoa::world {

// Maps a client world opcode to its mangos 1.12 equivalent.
// Returns -1 to drop the packet (client-only opcode mangos does not understand).
// Auth and ping share vanilla numbers; only the char-select flow differs so far.
inline int mapClientOpcode(int clientOpcode) {
    switch (clientOpcode) {
        case 0x060: return 0x037;   // char list request -> CMSG_CHAR_ENUM
        case 0x111: return -1;      // client keepalive -> drop
    }
    // Client-specific opcodes sit above the vanilla 1.12 range. mangos rejects them as
    // malformed and closes the socket, so drop them until each is individually mapped
    // (e.g. 0x340 handshake, 0x4EE char-select).
    if (clientOpcode >= 0x300) return -1;
    return clientOpcode;            // assume a shared vanilla opcode
}

// Maps a mangos 1.12 opcode to the client's world opcode. Identity unless the client
// uses a different number for that message.
inline int mapServerOpcode(int serverOpcode) {
    switch (serverOpcode) {
        case 0x03B: return 0x271;   // SMSG_CHAR_ENUM -> client char list
        default:    return serverOpcode;
    }
}

} // namespace uoa::world
