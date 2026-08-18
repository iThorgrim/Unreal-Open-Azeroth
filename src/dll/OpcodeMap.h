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
        // World-ready ack: a client<->proxy handshake answered locally with the pawn-spawn (0x102), never
        // forwarded (mangos 0x103 is SMSG_EMOTE, a server opcode it logs as unhandled).
        case op::client::kWorldReadyAck:  return -1;
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

// Maps a mangos 1.12 opcode to the client's world opcode, or -1 to drop it. The char-select flow is
// renumbered (SMSG_CHAR_ENUM 0x3B -> 0x478, etc.) and the compressed object stream only reaches a live
// handler at 0x1FC (the vanilla 0x1F6 slot is an inert stub, so an unrenumbered update never spawns the
// pawn). Everything else is forwarded under its vanilla number: the reference server suppresses the
// post-login init/world-state burst, but that server drives possession natively; against vmangos the
// client may in fact need that burst to reach world-ready, so we stop dropping it and let it through.
// Only two classes are still dropped, because forwarding them raw actively corrupts state rather than
// merely hitting a stub:
//   - the classic movement/spell bodies (SMSG_MONSTER_MOVE and friends), which arrive continuously and
//     whose coordinates land in unrelated actor fields on the UE-replicated x64 client;
//   - uncompressed SMSG_UPDATE_OBJECT, which has no live raw handler and would need deflate to re-emit as
//     a 0x1FC frame; the initial (already compressed) scene create still spawns the pawn without it.
inline int mapServerOpcode(int serverOpcode)
{
    switch (serverOpcode) {
        case op::mangos::kSMSG_COMPRESSED_UPDATE_OBJECT: return op::client::kCompressedUpdate; // 0x1FC
        case op::mangos::kSMSG_INITIAL_SPELLS:         return op::client::kInitialSpells;  // 0x2EB (spellbook)
        case op::mangos::kSMSG_ACTION_BUTTONS:         return op::client::kActionButtons;  // 0x4FA (action bars)
        case op::mangos::kSMSG_CHAR_ENUM:              return op::client::kCharEnumResp;   // 0x478
        case op::mangos::kSMSG_CHAR_CREATE:            return op::client::kCharCreateResp; // 0x232
        case op::mangos::kSMSG_CHAR_DELETE:            return op::client::kCharDeleteResp; // 0x233
        case op::mangos::kSMSG_CHAR_RENAME:            return op::client::kCharRenameResp; // 0x3C3
        case op::mangos::kSMSG_CHARACTER_LOGIN_FAILED: return op::client::kLoginFailed;    // 0x216
        case op::mangos::kSMSG_LOGIN_VERIFY_WORLD:     return op::client::kMapVerify;      // 0x0C5 (this build's map-verify slot; 0x236 is an unregistered stub)

        case op::mangos::kSMSG_UPDATE_OBJECT:           // 0x0A9 (needs deflate into 0x1FC)
        case op::mangos::kSMSG_MONSTER_MOVE:            // 0x0DD
        case op::mangos::kSMSG_MONSTER_MOVE_TRANSPORT:  // 0x2AE
        case op::mangos::kSMSG_SPELL_START:             // 0x131
        case op::mangos::kSMSG_SPELL_GO:                // 0x132
        case op::mangos::kSMSG_SPLINE_MOVE_ROOT:        // 0x31A
            return -1;
        default: break;
    }
    if (serverOpcode >= op::mangos::kSMSG_SPLINE_MOVE_FIRST &&
        serverOpcode <= op::mangos::kSMSG_SPLINE_MOVE_LAST) return -1;   // 0x304..0x30E

    return serverOpcode;   // forward under the vanilla number
}

} // namespace uoa::world
