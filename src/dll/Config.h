#pragma once

// Fixed endpoints and identifiers for the interop layer.
namespace uoa::config {

inline constexpr unsigned short kRealmdPort = 3724;  // stock realmd
inline constexpr unsigned short kWorldPort  = 8085;  // stock mangosd
inline constexpr unsigned short kProxyAuth  = 3728;  // internal auth proxy
inline constexpr unsigned short kProxyWorld = 3729;  // internal world proxy
inline constexpr unsigned short kBuild      = 5875;  // client build reported to realmd

inline constexpr const char* kWorldAddr = "127.0.0.1:8085";        // real world addr; connect hook redirects 8085 -> world proxy
inline constexpr const char* kLogFile   = "UnrealOpenAzeroth.log";

} // namespace uoa::config
