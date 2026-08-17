#include "Settings.h"
#include "Log.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>

namespace uoa {

Settings& settings() {
    static Settings instance;
    return instance;
}

// Candidate paths for a .wtf config: next to the exe, then a few parent folders.
static std::vector<std::string> configPaths(const char* name) {
    char exe[MAX_PATH];
    GetModuleFileNameA(GetModuleHandleA(nullptr), exe, MAX_PATH);

    std::string dir(exe);
    if (size_t slash = dir.find_last_of("\\/"); slash != std::string::npos)
        dir.resize(slash);

    std::vector<std::string> paths = { name };
    for (int i = 0; i < 5; ++i) {
        paths.push_back(dir + "\\" + name);
        size_t up = dir.find_last_of("\\/");
        if (up == std::string::npos) break;
        dir.resize(up);
    }
    return paths;
}

void loadRealmlist() {
    for (const std::string& path : configPaths("realmlist.wtf")) {
        FILE* f = fopen(path.c_str(), "rb");
        if (!f) continue;

        char line[256];
        while (fgets(line, sizeof line, f)) {
            std::string lower(line);
            for (char& c : lower) c = char(tolower((unsigned char)c));
            size_t pos = lower.find("realmlist");
            if (pos == std::string::npos) continue;

            char* p = line + pos + 9;   // skip "realmlist"
            while (*p == ' ' || *p == '\t' || *p == '=' || *p == '"') ++p;

            char host[128];
            int n = 0;
            while (*p && *p != ' ' && *p != '\t' && *p != '"' && *p != '\r' && *p != '\n' && n < 127)
                host[n++] = *p++;
            host[n] = 0;

            if (n > 0) {
                settings().forwardHost = host;
                fclose(f);
                log::line("[dll] realmlist.wtf: server = %s  (%s)", host, path.c_str());
                return;
            }
        }
        fclose(f);
    }
    log::line("[dll] realmlist.wtf missing -> default %s", settings().forwardHost.c_str());
}

// Maps a discord.wtf "type" value to a Discord activity type.
static int32_t activityType(const std::string& value) {
    std::string t;
    for (char c : value) t += char(tolower((unsigned char)c));
    if (t == "playing")   return 0;
    if (t == "streaming") return 1;
    if (t == "listening") return 2;
    if (t == "watching")  return 3;
    if (t == "custom" || t == "customstatus") return 4;
    if (t == "competing") return 5;
    return atoi(value.c_str());
}

void loadDiscordConfig() {
    Settings& s = settings();
    for (const std::string& path : configPaths("discord.wtf")) {
        FILE* f = fopen(path.c_str(), "rb");
        if (!f) continue;

        char line[512];
        while (fgets(line, sizeof line, f)) {
            char* p = line;
            while (*p == ' ' || *p == '\t') ++p;
            if (*p == '#' || *p == ';' || *p == '\r' || *p == '\n' || !*p) continue;

            char key[32];
            int k = 0;
            while (*p && *p != ' ' && *p != '\t' && *p != '=' && k < 31)
                key[k++] = char(tolower((unsigned char)*p++));
            key[k] = 0;

            while (*p == ' ' || *p == '\t' || *p == '=') ++p;
            std::string value(p);
            while (!value.empty() && (value.back() == '\r' || value.back() == '\n' || value.back() == ' '))
                value.pop_back();

            if      (!strcmp(key, "details")) { s.details = value; s.hasDetails = true; }
            else if (!strcmp(key, "state"))   { s.state   = value; s.hasState   = true; }
            else if (!strcmp(key, "type"))    { s.type = activityType(value); s.hasType = true; }
            else if (!strcmp(key, "application_id") || !strcmp(key, "app_id")) {
                s.appId = _strtoui64(value.c_str(), nullptr, 10);
                s.hasAppId = (s.appId != 0);
            }
        }
        fclose(f);
        const char* details = s.hasDetails ? s.details.c_str() : "(unchanged)";
        const char* state   = s.hasState ? s.state.c_str() : "(unchanged)";
        log::line("[discord] discord.wtf: details=\"%s\" state=\"%s\" type=%d app_id=%llu  (%s)", details, state, s.hasType ? s.type : -1, (unsigned long long)s.appId, path.c_str());
        return;
    }
    log::line("[discord] discord.wtf missing -> presence unchanged");
}

void loadWorldConfig() {
    Settings& s = settings();
    for (const std::string& path : configPaths("world.wtf")) {
        FILE* f = fopen(path.c_str(), "rb");
        if (!f) continue;

        char line[256];
        while (fgets(line, sizeof line, f)) {
            char* p = line;
            while (*p == ' ' || *p == '\t') ++p;
            if (*p == '#' || *p == ';' || *p == '\r' || *p == '\n' || !*p) continue;

            char key[32];
            int k = 0;
            while (*p && *p != ' ' && *p != '\t' && *p != '=' && k < 31)
                key[k++] = char(tolower((unsigned char)*p++));
            key[k] = 0;

            while (*p == ' ' || *p == '\t' || *p == '=') ++p;

            if (!strcmp(key, "charenum") || !strcmp(key, "charenum_opcode"))
                s.charEnumOpcode = (int)strtol(p, nullptr, 0);   // base 0: accepts 0x.. or decimal
        }
        fclose(f);
        log::line("[world] world.wtf: charenum=0x%03X  (%s)", s.charEnumOpcode, path.c_str());
        return;
    }
    log::line("[world] world.wtf missing -> charenum=0x%03X (default)", s.charEnumOpcode);
}

} // namespace uoa
