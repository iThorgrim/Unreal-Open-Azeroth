#pragma once
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

// Maps a mangos 1.12 opcode to the client's world opcode. Most server->client opcodes share their
// vanilla numbers, but some in the char-select flow are renumbered and must be relabelled or the client
// ignores the packet: SMSG_CHAR_ENUM (0x3B) is the client's 0x478 (its scene-load opcode is 0x271, so
// relabelling to that drove a world-load with free camera and no UI instead of the char list).
inline int mapServerOpcode(int serverOpcode)
{
    switch (serverOpcode) {
        case op::mangos::kSMSG_CHAR_ENUM:   return op::client::kCharEnumResp;     // 0x478
        case op::mangos::kSMSG_CHAR_CREATE: return op::client::kCharCreateResp;   // 0x232
        case op::mangos::kSMSG_CHAR_DELETE: return op::client::kCharDeleteResp;   // 0x233
    }
    return serverOpcode;
}

} // namespace uoa::world
