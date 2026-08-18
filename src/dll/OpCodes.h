#pragma once
#include <cstdint>

// Central opcode registry for both protocol surfaces the proxy speaks.
//
//  - azrt::  the client's AZRT auth channel (custom to this client, N/g=2 SRP). These are wire
//            constants, stable across client builds - only their in-binary handler addresses shift
//            between versions, and those live in Offsets.h. resolve_offsets.py dumps the client's
//            dispatch table so the set here can be cross-checked after an update.
//  - mangos::/client::  the world channel: mangos 1.12 opcodes and the client's renumbered world
//            opcodes, remapped against each other in OpcodeMap.h.
namespace uoa::op {

// ---- AZRT auth channel ----
// Direction is relative to the proxy: (S->C) the proxy sends, (C->S) the client sends.
namespace azrt {
inline constexpr uint8_t kSessionOpen   = 0xA0;   // C->S  first byte: opens the AZRT auth session
inline constexpr uint8_t kChallenge     = 0xA1;   // S->C  SRP challenge: B, N, salt, g, AZCT token
inline constexpr uint8_t kChallengeReply = 0xA2;  // C->S  client answer: A + M1
inline constexpr uint8_t kProof         = 0xA3;   // S->C  proof result: status + M2
inline constexpr uint8_t kTicket        = 0xA5;   // S->C  secure-channel key exchange (AZ-TICKET-v1)
inline constexpr uint8_t kKeyAck        = 0xA6;   // both  client key ack, and the proxy's ack reply
inline constexpr uint8_t kSession       = 0xA7;   // S->C  session flag (one byte; 0 = proceed)
inline constexpr uint8_t kKeyInstall    = 0xA8;   // S->C  install world session key, advance to state 5
inline constexpr uint8_t kKeyInstallAck = 0xA9;   // C->S  client ack of the key install (58 bytes)
inline constexpr uint8_t kRealmListReq  = 0xB0;   // C->S  realm-list request
inline constexpr uint8_t kRealmList     = 0xB1;   // S->C  realm-list reply
}

// ---- classic realmd commands (proxy <-> cmangos realmd, hat-2) ----
namespace realmd {
inline constexpr uint8_t kLogonChallenge = 0x00;   // CMD_AUTH_LOGON_CHALLENGE
inline constexpr uint8_t kLogonProof     = 0x01;   // CMD_AUTH_LOGON_PROOF
inline constexpr uint8_t kRealmList      = 0x10;   // CMD_REALM_LIST
}

// ---- mangos 1.12 world opcodes ----
namespace mangos {
inline constexpr int kCMSG_CHAR_ENUM      = 0x037;
inline constexpr int kCMSG_CHAR_CREATE    = 0x036;
inline constexpr int kCMSG_CHAR_DELETE     = 0x038;
inline constexpr int kCMSG_PLAYER_LOGIN    = 0x03D;   // client->server: enter world with the selected char
inline constexpr int kCMSG_NAME_QUERY      = 0x050;   // client->server: u64 guid (response is 0x051)
inline constexpr int kCMSG_GAMEOBJECT_QUERY = 0x05E;  // client->server: u32 entry + u64 guid (response is 0x05F)
inline constexpr int kCMSG_CREATURE_QUERY  = 0x060;   // client->server: u32 entry + u64 guid (response is 0x061)
inline constexpr int kCMSG_SET_SELECTION   = 0x13D;   // client->server: u64 guid of the targeted unit
inline constexpr int kCMSG_ZONEUPDATE      = 0x1F4;   // client->server: u32 zone id
inline constexpr int kCMSG_SET_ACTIVE_MOVER = 0x26A;  // client->server: u64 guid of the unit the client moves
inline constexpr int kCMSG_PING            = 0x1DC;
inline constexpr int kSMSG_CHAR_ENUM      = 0x03B;
inline constexpr int kSMSG_CHAR_CREATE    = 0x03A;   // server->client: 1-byte char-create result code
inline constexpr int kSMSG_CHAR_DELETE    = 0x03C;   // server->client: 1-byte char-delete result code
inline constexpr int kSMSG_AUTH_CHALLENGE = 0x1EC;   // server->client: carries the u32 auth seed
inline constexpr int kCMSG_AUTH_SESSION   = 0x1ED;   // client->server: build, account, clientSeed, digest
inline constexpr int kSMSG_AUTH_RESPONSE  = 0x1EE;   // server->client: first header-crypted server frame

// server->client world stream. The x64 client owns movement (UE-replicated) and only reads the object
// stream through one renumbered handler, so these are remapped or dropped rather than forwarded verbatim.
inline constexpr int kSMSG_UPDATE_OBJECT            = 0x0A9;   // uncompressed object update
inline constexpr int kSMSG_COMPRESSED_UPDATE_OBJECT = 0x1F6;   // zlib(u32 rawSize + deflate) object update
inline constexpr int kSMSG_INITIAL_SPELLS          = 0x12A;    // spellbook init: u8 + u16 count + spell/cooldown lists
inline constexpr int kSMSG_ACTION_BUTTONS          = 0x129;    // action-bar init: 120 x u32, no length prefix
inline constexpr int kSMSG_LOGIN_VERIFY_WORLD      = 0x236;    // map id + spawn position + orientation
inline constexpr int kSMSG_MONSTER_MOVE            = 0x0DD;    // spline move; classic body corrupts the x64 actor
inline constexpr int kSMSG_MONSTER_MOVE_TRANSPORT  = 0x2AE;
inline constexpr int kSMSG_SPELL_START             = 0x131;
inline constexpr int kSMSG_SPELL_GO                = 0x132;
inline constexpr int kSMSG_SPLINE_MOVE_FIRST       = 0x304;    // contiguous spline-move state block, 0x304..0x30E
inline constexpr int kSMSG_SPLINE_MOVE_LAST        = 0x30E;
inline constexpr int kSMSG_SPLINE_MOVE_ROOT        = 0x31A;    // numbered apart from the block

// server->client the client has a live handler for. Everything else lands on an inert stub, so it is
// dropped rather than forwarded (a stub can still perturb the world-entry state machine).
inline constexpr int kSMSG_MESSAGECHAT                = 0x096;  // 150  MOTD / chat
inline constexpr int kSMSG_CHARACTER_LOGIN_FAILED     = 0x041;  // 65
inline constexpr int kSMSG_NAME_QUERY_RESPONSE        = 0x051;  // 81
inline constexpr int kSMSG_ITEM_QUERY_SINGLE_RESPONSE = 0x058;  // 88
inline constexpr int kSMSG_GAMEOBJECT_QUERY_RESPONSE  = 0x05F;  // 95
inline constexpr int kSMSG_CREATURE_QUERY_RESPONSE    = 0x061;  // 97
inline constexpr int kSMSG_CHAR_RENAME                = 0x2C8;  // 712
}

// ---- client (UE) world opcodes ----
// The client renumbers world opcodes on BOTH directions. Auth/ping keep vanilla numbers, but the
// char-select flow is renumbered each way and must be remapped in OpcodeMap.h or the client ignores the
// packet. Values read from the client's own dispatch tables (C->S packet ctor / S->C handler table).
namespace client {
inline constexpr int kCharListReq   = 0x060;   // C->S -> CMSG_CHAR_ENUM
inline constexpr int kPing          = 0x111;   // C->S -> CMSG_PING
inline constexpr int kCharCreate    = 0x299;   // C->S -> CMSG_CHAR_CREATE
inline constexpr int kCharDelete    = 0x221;   // C->S -> CMSG_CHAR_DELETE
inline constexpr int kPlayerLogin   = 0x4EE;   // C->S -> CMSG_PLAYER_LOGIN (guid + locale)
inline constexpr int kCreatureQuery = 0x0DE;   // C->S -> CMSG_CREATURE_QUERY (u32 entry + u64 guid)
inline constexpr int kQueryEntry2   = 0x05D;   // C->S -> CMSG_CREATURE_QUERY (same query-by-entry body)
inline constexpr int kQueryEntry3   = 0x143;   // C->S -> CMSG_CREATURE_QUERY (same query-by-entry body)
inline constexpr int kSetActiveMover = 0x011;  // C->S -> CMSG_SET_ACTIVE_MOVER (u64 guid the client controls)
inline constexpr int kSetSelection  = 0x159;   // C->S -> CMSG_SET_SELECTION (u64 guid)
inline constexpr int kZoneUpdate    = 0x1AB;   // C->S -> CMSG_ZONEUPDATE (u32 zone id)
inline constexpr int kWorldReadyAck = 0x103;   // C->S world-ready ack (empty body): the client signals it has
                                               // built its scene and asks for its pawn. It is a client<->proxy
                                               // handshake, not a server opcode, so it is answered with 0x102
                                               // (not forwarded to mangos, whose 0x103 is the unrelated SMSG_EMOTE)
inline constexpr int kQueryByGuid   = 0x4FB;   // C->S -> name/creature/GO query; body is the full 8-byte guid,
                                               // which encodes the template entry (bits [47:24]) the query needs
inline constexpr int kCharEnumResp  = 0x478;   // S->C <- SMSG_CHAR_ENUM
inline constexpr int kCharCreateResp = 0x232;  // S->C <- SMSG_CHAR_CREATE
inline constexpr int kCharDeleteResp = 0x233;  // S->C <- SMSG_CHAR_DELETE
inline constexpr int kCharRenameResp = 0x3C3;  // S->C <- SMSG_CHAR_RENAME
inline constexpr int kLoginFailed    = 0x216;  // S->C <- SMSG_CHARACTER_LOGIN_FAILED
inline constexpr int kAzctProbe      = 0x1A4;  // S->C AZCT probe; the client accepts it only when empty
inline constexpr int kCompressedUpdate = 0x1FC; // S->C <- SMSG_(COMPRESSED_)UPDATE_OBJECT; the live update handler
                                                // (the vanilla 0x1F6 slot is an inert stub, so the pawn never spawns)
inline constexpr int kInitialSpells    = 0x2EB; // S->C <- SMSG_INITIAL_SPELLS; handler builds the spellbook (u8+u16 count+lists)
inline constexpr int kActionButtons    = 0x4FA; // S->C <- SMSG_ACTION_BUTTONS; handler reads 120 x u32 into the action-bar manager
inline constexpr int kWorldAccess      = 0x527; // S->C injected before LOGIN_VERIFY_WORLD to lift the world gate
                                                // (u8 != 0 = granted, u32 = 0 = no countdown); 0x236 alone does not
                                                // start the map/NPC stream
inline constexpr int kMapVerify        = 0x0C5; // S->C <- SMSG_LOGIN_VERIFY_WORLD. This build wires the map-verify
                                                // handler (reads mapId, validates the map, flips world-ready -> 2,
                                                // which drives possession) at opcode 0x0C5; the 0x236 slot is an
                                                // unregistered stub here (that slot needs the Emberveil client patch)
inline constexpr int kMapReadyPawn     = 0x102; // S->C synthesized after 0x0C5: the client requests it (via 0x103)
                                                // to spawn/position its own pawn. Body = u32 actor id (player guid-low);
                                                // the handler applies a default transform. 0x0C5 only validates the map
                                                // and does not place the pawn (welder's patched 0x236 did both inline)
}

} // namespace uoa::op
