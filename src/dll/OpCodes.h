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
// Auth handshake plus the char-select flow only; the world/in-game stream is out of scope for this proxy.
namespace mangos {
inline constexpr int kCMSG_CHAR_ENUM      = 0x037;
inline constexpr int kCMSG_CHAR_CREATE    = 0x036;
inline constexpr int kCMSG_CHAR_DELETE    = 0x038;
inline constexpr int kCMSG_PING           = 0x1DC;
inline constexpr int kSMSG_CHAR_ENUM      = 0x03B;
inline constexpr int kSMSG_CHAR_CREATE    = 0x03A;   // server->client: 1-byte char-create result code
inline constexpr int kSMSG_CHAR_DELETE    = 0x03C;   // server->client: 1-byte char-delete result code
inline constexpr int kSMSG_AUTH_CHALLENGE = 0x1EC;   // server->client: carries the u32 auth seed
inline constexpr int kCMSG_AUTH_SESSION   = 0x1ED;   // client->server: build, account, clientSeed, digest
inline constexpr int kSMSG_AUTH_RESPONSE  = 0x1EE;   // server->client: first header-crypted server frame
inline constexpr int kSMSG_CHARACTER_LOGIN_FAILED = 0x041;  // 65
inline constexpr int kSMSG_CHAR_RENAME    = 0x2C8;   // 712
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
inline constexpr int kCharEnumResp  = 0x478;   // S->C <- SMSG_CHAR_ENUM
inline constexpr int kCharCreateResp = 0x232;  // S->C <- SMSG_CHAR_CREATE
inline constexpr int kCharDeleteResp = 0x233;  // S->C <- SMSG_CHAR_DELETE
inline constexpr int kCharRenameResp = 0x3C3;  // S->C <- SMSG_CHAR_RENAME
inline constexpr int kLoginFailed    = 0x216;  // S->C <- SMSG_CHARACTER_LOGIN_FAILED
}

} // namespace uoa::op
