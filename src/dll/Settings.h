#pragma once
#include <cstdint>
#include <string>

namespace uoa {

// Runtime configuration loaded from realmlist.wtf and discord.wtf.
struct Settings {
    // Forward target: the server the proxies connect to (from realmlist.wtf).
    std::string forwardHost = "127.0.0.1";

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

void loadRealmlist();      // fills forwardHost
void loadDiscordConfig();  // fills the discord fields

} // namespace uoa
