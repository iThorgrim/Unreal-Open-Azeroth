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
        case op::client::kCharDelete:    return op::mangos::kCMSG_CHAR_DELETE;    // u64 guid, vanilla-shaped
        case op::client::kPlayerLogin:   return op::mangos::kCMSG_PLAYER_LOGIN;   // u64 guid (enter world)
        // In-world control. Without these the client's renumbered opcodes collide with unrelated vanilla
        // ids (0x11 -> CMSG_CREATEMONSTER, 0x143 -> SMSG_ATTACKSTART, 0x1AB -> SMSG_TAXINODE_STATUS...) and
        // the server rejects them, so the client never binds its mover, selection or zone.
        case op::client::kSetActiveMover: return op::mangos::kCMSG_SET_ACTIVE_MOVER; // u64 guid
        case op::client::kSetSelection:   return op::mangos::kCMSG_SET_SELECTION;     // u64 guid
        case op::client::kZoneUpdate:     return op::mangos::kCMSG_ZONEUPDATE;        // u32 zone id
        // The client issues three distinct opcodes for a template query, each carrying a u32 entry + u64
        // guid. The real server picks creature/gameobject/item by which template owns the entry; lacking
        // that table here, all resolve to the creature query, so gameobject and item names may be missing.
        case op::client::kCreatureQuery:
        case op::client::kQueryEntry2:
        case op::client::kQueryEntry3:    return op::mangos::kCMSG_CREATURE_QUERY;    // u32 entry + u64 guid
    }
    // Client-specific opcodes sit above the vanilla 1.12 range. mangos rejects them as
    // malformed and closes the socket, so drop them until each is individually mapped
    // (e.g. 0x4FB query-by-guid, which needs the guid decoded to an entry first).
    if (clientOpcode >= 0x300) return -1;
    return clientOpcode;            // assume a shared vanilla opcode
}

// Maps a mangos 1.12 opcode to the client's world opcode, or -1 to drop it. Most server->client opcodes
// share their vanilla numbers, but the char-select flow is renumbered (SMSG_CHAR_ENUM 0x3B -> 0x478, etc.)
// and the world stream needs three corrections the x64 client depends on:
//   - the object stream only reaches a live handler at 0x1FC; the vanilla 0x1F6 slot is an inert stub, so an
//     unrenumbered compressed update is silently discarded and the pawn never spawns;
//   - the client owns movement (UE-replicated), so the classic spline/spell bodies are dropped rather than
//     applied against the wrong actor fields (their coordinates otherwise land in unrelated slots);
//   - uncompressed SMSG_UPDATE_OBJECT has no live client handler and must be re-emitted through 0x1FC as a
//     compressed frame, which needs deflate; until that path exists it is dropped, so single-object deltas
//     are deferred while the initial (already compressed) scene create still spawns the pawn.
inline int mapServerOpcode(int serverOpcode)
{
    switch (serverOpcode) {
        case op::mangos::kSMSG_MONSTER_MOVE:
        case op::mangos::kSMSG_MONSTER_MOVE_TRANSPORT:
        case op::mangos::kSMSG_SPELL_START:
        case op::mangos::kSMSG_SPELL_GO:
        case op::mangos::kSMSG_SPLINE_MOVE_ROOT:
        case op::mangos::kSMSG_UPDATE_OBJECT:
            return -1;
    }
    if (serverOpcode >= op::mangos::kSMSG_SPLINE_MOVE_FIRST &&
        serverOpcode <= op::mangos::kSMSG_SPLINE_MOVE_LAST)
        return -1;

    switch (serverOpcode) {
        case op::mangos::kSMSG_COMPRESSED_UPDATE_OBJECT: return op::client::kCompressedUpdate; // 0x1FC
        case op::mangos::kSMSG_CHAR_ENUM:   return op::client::kCharEnumResp;     // 0x478
        case op::mangos::kSMSG_CHAR_CREATE: return op::client::kCharCreateResp;   // 0x232
        case op::mangos::kSMSG_CHAR_DELETE: return op::client::kCharDeleteResp;   // 0x233
    }
    return serverOpcode;
}

} // namespace uoa::world
