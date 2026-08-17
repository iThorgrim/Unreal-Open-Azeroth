#pragma once
#include <cstdint>
#include <string>

namespace uoa {

// Runtime configuration loaded from realmlist.wtf, discord.wtf and world.wtf.
struct Settings {
    // Forward target: the server the proxies connect to (from realmlist.wtf).
    std::string forwardHost = "127.0.0.1";

    // World-protocol tuning (from world.wtf): the opcode we relabel mangos's vanilla SMSG_CHAR_ENUM
    // (0x3B) to, matching the client's renumbered char-enum result.
    int charEnumOpcode = 0x03B;

    // Discord presence overrides (from discord.wtf). Each field is applied only if set.
    bool        hasDetails = false;
    bool        hasState   = false;
    bool        hasType    = false;
    bool        hasAppId   = false;
    std::string details;
    std::string state;
    int32_t     type  = 0;
    uint64_t    appId = 0;

};

Settings& settings();

void loadRealmlist();        // fills forwardHost
void loadDiscordConfig();    // fills the discord fields
void loadWorldConfig();      // fills the world-protocol fields

} // namespace uoa
