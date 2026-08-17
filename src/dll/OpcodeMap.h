#pragma once
#include "Settings.h"
#include "OpCodes.h"

namespace uoa::world {

// Maps a client world opcode to its mangos 1.12 equivalent.
// Returns -1 to drop the packet (client-only opcode mangos does not understand).
// Auth and ping share vanilla numbers; only the char-select flow differs so far.
inline int mapClientOpcode(int clientOpcode)
{
    switch (clientOpcode) {
        case op::client::kCharListReq: return op::mangos::kCMSG_CHAR_ENUM;
        case op::client::kPing:        return op::mangos::kCMSG_PING;      // uint32 seq + uint32 latency
        case op::client::kCharCreate:  return op::mangos::kCMSG_CHAR_CREATE;  // name + 9 bytes, vanilla-shaped
        case op::client::kCharDelete:  return op::mangos::kCMSG_CHAR_DELETE;  // u64 guid, vanilla-shaped
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
inline int mapServerOpcode(int serverOpcode)
{
    if (serverOpcode == op::mangos::kSMSG_CHAR_ENUM) return settings().charEnumOpcode;
    return serverOpcode;
}

} // namespace uoa::world
