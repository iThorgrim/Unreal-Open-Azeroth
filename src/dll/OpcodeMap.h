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
    // Client-specific opcodes sit above the vanilla 1.12 range. mangos rejects them as malformed and closes
    // the socket, so drop everything past char-select: the mission stops at the licence, and forwarding a
    // world opcode raw would only harm a mangos session that never expects it.
    if (clientOpcode >= 0x300) return -1;
    return clientOpcode;            // assume a shared vanilla opcode
}

// Maps a mangos 1.12 opcode to the client's world opcode. The char-select replies are renumbered
// (SMSG_CHAR_ENUM 0x3B -> 0x478, etc.); auth and ping keep their vanilla numbers and are forwarded as-is.
// The world/in-game stream is out of scope for this proxy, so nothing there is remapped.
inline int mapServerOpcode(int serverOpcode)
{
    switch (serverOpcode) {
        case op::mangos::kSMSG_CHAR_ENUM:              return op::client::kCharEnumResp;   // 0x478
        case op::mangos::kSMSG_CHAR_CREATE:            return op::client::kCharCreateResp; // 0x232
        case op::mangos::kSMSG_CHAR_DELETE:            return op::client::kCharDeleteResp; // 0x233
        case op::mangos::kSMSG_CHAR_RENAME:            return op::client::kCharRenameResp; // 0x3C3
        case op::mangos::kSMSG_CHARACTER_LOGIN_FAILED: return op::client::kLoginFailed;    // 0x216
        default: break;
    }
    return serverOpcode;   // forward under the vanilla number
}

} // namespace uoa::world
