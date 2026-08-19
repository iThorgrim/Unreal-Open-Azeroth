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

} // namespace uoa
