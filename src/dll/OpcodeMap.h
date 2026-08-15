#pragma once
#include "Settings.h"

namespace uoa::world {

// Maps a client world opcode to its mangos 1.12 equivalent.
// Returns -1 to drop the packet (client-only opcode mangos does not understand).
// Auth and ping share vanilla numbers; only the char-select flow differs so far.
inline int mapClientOpcode(int clientOpcode) {
    switch (clientOpcode) {
        case 0x060: return 0x037;   // char list request -> CMSG_CHAR_ENUM
        case 0x111: return 0x1DC;   // ping (uint32 seq + uint32 latency) -> CMSG_PING
        case 0x299: return 0x036;   // create character (name + 9 bytes, vanilla-shaped) -> CMSG_CHAR_CREATE
        case 0x221: return 0x038;   // delete character (u64 guid, vanilla-shaped) -> CMSG_CHAR_DELETE
    }
    // Client-specific opcodes sit above the vanilla 1.12 range. mangos rejects them as
    // malformed and closes the socket, so drop them until each is individually mapped
    // (e.g. 0x340 handshake, 0x4EE locale announce "en").
    if (clientOpcode >= 0x300) return -1;
    return clientOpcode;            // assume a shared vanilla opcode
}

// Maps a mangos 1.12 opcode to the client's world opcode. The client keeps server->client
// opcodes at their vanilla numbers (only its client->server side is renumbered), so this is
// identity. Notably SMSG_CHAR_ENUM stays 0x3B: relabelling it to 0x271 drove a world-load
// (free camera, no UI), because 0x271 is the client's scene-load opcode, not the char list.
inline int mapServerOpcode(int serverOpcode) {
    if (serverOpcode == 0x03B) return settings().charEnumOpcode;   // char-enum result -> client's number
    return serverOpcode;
}

} // namespace uoa::world
