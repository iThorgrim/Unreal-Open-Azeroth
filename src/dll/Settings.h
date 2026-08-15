#pragma once
#include <cstdint>
#include <string>

namespace uoa {

// Runtime configuration loaded from realmlist.wtf, discord.wtf and world.wtf.
struct Settings {
    // Forward target: the server the proxies connect to (from realmlist.wtf).
    std::string forwardHost = "127.0.0.1";

    // World-protocol tuning (from world.wtf). The client renumbers its char-enum result opcode;
    // this is the value we relabel mangos's vanilla SMSG_CHAR_ENUM (0x3B) to. Sweepable without a
    // rebuild until the right one is found (the client only reacts to its own number).
    int charEnumOpcode = 0x03B;

    // Discovery aid: when sweepHi > sweepLo, the char-enum result is emitted once under every opcode
    // in [sweepLo, sweepHi] at once, so a whole band can be tested per launch and bisected down to
    // the exact opcode. sweepLo == sweepHi (default) disables it and uses charEnumOpcode.
    int sweepLo = 0;
    int sweepHi = 0;

    // Auto-sweep: when set, the band advances itself by sweepStep on every launch (persisted in a
    // state file), scanning [sweepStart, sweepEnd) without any manual world.wtf edits. Just relaunch;
    // the log names the active band. Overrides sweepLo/sweepHi.
    bool autoSweep  = false;
    int  sweepStep  = 0x40;
    int  sweepStart = 0x40;
    int  sweepEnd   = 0x526;
    int  sweepTarget = 0x3B;   // which S->C opcode the sweep relabels/sprays (char-enum by default)
    bool sweepZero   = true;   // fill the sprayed body with zeros (char-enum); set 0 to keep the
                               // real body when sweeping a small result opcode (e.g. char-create 0x3A)

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
void advanceSweepCursor();   // in auto-sweep mode, pick this launch's band and store the next

} // namespace uoa
