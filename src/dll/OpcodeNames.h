#pragma once
#include "OpCodes.h"

// Human names for world opcodes, for log annotation only (never protocol logic). Covers the vanilla
// 1.12 opcodes of the connect -> char-select -> world-entry flow plus the client's renumbered
// client->server opcodes; returns nullptr for anything not yet catalogued, so the log falls back to the
// raw number. Extend as new opcodes are identified from the annotated log.
namespace uoa::op {

// `fromClient` picks the right meaning for a renumbered opcode: the client renumbers only its
// client->server side, so the same number can mean different things per direction.
inline const char* worldName(int op, bool fromClient) {
    if (fromClient) {
        switch (op) {
            case client::kCharListReq: return "client:CharListReq";
            case client::kPing:        return "client:Ping";
            case client::kCharCreate:  return "client:CharCreate";
            case client::kCharDelete:  return "client:CharDelete";
        }
    }
    switch (op) {
        case 0x036: return "CMSG_CHAR_CREATE";
        case 0x037: return "CMSG_CHAR_ENUM";
        case 0x038: return "CMSG_CHAR_DELETE";
        case 0x03A: return "SMSG_CHAR_CREATE";
        case 0x03B: return "SMSG_CHAR_ENUM";
        case 0x03C: return "SMSG_CHAR_DELETE";
        case 0x03D: return "CMSG_PLAYER_LOGIN";
        case 0x03E: return "SMSG_NEW_WORLD";
        case 0x041: return "SMSG_CHARACTER_LOGIN_FAILED";
        case 0x04B: return "CMSG_LOGOUT_REQUEST";
        case 0x050: return "CMSG_NAME_QUERY";
        case 0x051: return "SMSG_NAME_QUERY_RESPONSE";
        case 0x1DC: return "CMSG_PING";
        case 0x1DD: return "SMSG_PONG";
        case 0x1EC: return "SMSG_AUTH_CHALLENGE";
        case 0x1ED: return "CMSG_AUTH_SESSION";
        case 0x1EE: return "SMSG_AUTH_RESPONSE";
        case 0x236: return "SMSG_LOGIN_VERIFY_WORLD";
    }
    return nullptr;
}

} // namespace uoa::op
