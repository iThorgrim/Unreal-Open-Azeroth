#pragma once
#include <cstdint>
#include <string>

namespace uoa {

// Runtime configuration loaded from realmlist.wtf.
struct Settings {
    // Forward target: the server the proxies connect to (from realmlist.wtf).
    std::string forwardHost = "127.0.0.1";
};

Settings& settings();

void loadRealmlist();        // fills forwardHost

} // namespace uoa
