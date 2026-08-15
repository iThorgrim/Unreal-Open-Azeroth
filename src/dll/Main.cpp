// UnrealOpenAzeroth.dll - entry point and boot orchestration.
#include "Config.h"
#include "Log.h"
#include "Settings.h"
#include "ConnectHook.h"
#include "WorldKey.h"
#include "AuthProxy.h"
#include "WorldProxy.h"
#include "DiscordPresence.h"

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstdint>

namespace {

using namespace uoa;

DWORD WINAPI authThread(LPVOID p)  { auth::handleSession((SOCKET)(uintptr_t)p);  return 0; }
DWORD WINAPI worldThread(LPVOID p) { world::handleSession((SOCKET)(uintptr_t)p); return 0; }

struct Listener { unsigned short port; const char* label; LPTHREAD_START_ROUTINE handler; };

// Accepts local connections on one port and hands each to a handler thread.
DWORD WINAPI listenerThread(LPVOID param) {
    Listener listener = *(Listener*)param;

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int reuse = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof reuse);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(listener.port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    bind(s, (sockaddr*)&addr, sizeof addr);
    listen(s, 8);
    log::line("[dll] proxy %s 127.0.0.1:%u", listener.label, listener.port);

    for (;;) {
        SOCKET c = accept(s, nullptr, nullptr);
        if (c != INVALID_SOCKET) CreateThread(nullptr, 0, listener.handler, (LPVOID)(uintptr_t)c, 0, nullptr);
    }
}

DWORD WINAPI boot(LPVOID) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    loadRealmlist();
    loadWorldConfig();
    advanceSweepCursor();

    static Listener authListener  { config::kProxyAuth,  "AUTH",  authThread };
    static Listener worldListener { config::kProxyWorld, "WORLD", worldThread };
    CreateThread(nullptr, 0, listenerThread, &authListener, 0, nullptr);
    CreateThread(nullptr, 0, listenerThread, &worldListener, 0, nullptr);

    Sleep(200);   // let the listeners bind before hooking connect
    hook::install();
    worldkey::install();

    loadDiscordConfig();
    discord::installAsync();

    log::line("[dll] UnrealOpenAzeroth ready.");
    return 0;
}

} // namespace

// The exe importing this symbol forces the loader to load the DLL at startup.
extern "C" __declspec(dllexport) void uoa_anchor() {}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(inst);
        uoa::log::init();
        uoa::log::line("[dll] === UnrealOpenAzeroth attach ===");
        CreateThread(nullptr, 0, boot, nullptr, 0, nullptr);
    }
    return TRUE;
}
