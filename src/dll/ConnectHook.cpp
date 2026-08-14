#include "ConnectHook.h"
#include "Config.h"
#include "Log.h"

#define WIN32_LEAN_AND_MEAN
#include <ws2tcpip.h>
#include <windows.h>
#include <MinHook.h>

namespace uoa::hook {

using WsaConnectFn = int (WSAAPI*)(SOCKET, const sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);

ConnectFn           realConnect    = nullptr;
static WsaConnectFn realWsaConnect = nullptr;

// Rewrites a realmd/world destination to the matching local proxy port.
static bool redirect(const sockaddr* name, sockaddr_in* out) {
    if (!name || name->sa_family != AF_INET) return false;

    const sockaddr_in* in = (const sockaddr_in*)name;
    unsigned short port = ntohs(in->sin_port);

    unsigned short proxyPort = 0;
    if      (port == config::kRealmdPort) proxyPort = config::kProxyAuth;
    else if (port == config::kWorldPort)  proxyPort = config::kProxyWorld;
    if (!proxyPort) return false;

    *out = *in;
    out->sin_port = htons(proxyPort);
    inet_pton(AF_INET, "127.0.0.1", &out->sin_addr);
    log::line("[hook] connect :%u -> 127.0.0.1:%u", port, proxyPort);
    return true;
}

static int WSAAPI hookConnect(SOCKET s, const sockaddr* name, int len) {
    sockaddr_in to;
    if (redirect(name, &to)) { name = (sockaddr*)&to; len = (int)sizeof to; }
    return realConnect(s, name, len);
}

static int WSAAPI hookWsaConnect(SOCKET s, const sockaddr* name, int len, LPWSABUF a, LPWSABUF b, LPQOS c, LPQOS d) {
    sockaddr_in to;
    if (redirect(name, &to)) { name = (sockaddr*)&to; len = (int)sizeof to; }
    return realWsaConnect(s, name, len, a, b, c, d);
}

static bool enable(const char* fn, void* target, void* detour, void** trampoline) {
    bool ok = target && MH_CreateHook(target, detour, trampoline) == MH_OK && MH_EnableHook(target) == MH_OK;
    log::line(ok ? "[hook] ws2_32!%s hooked" : "[hook] ws2_32!%s hook failed", fn);
    return ok;
}

bool install() {
    HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
    void* pConnect    = (void*)GetProcAddress(ws2, "connect");
    void* pWsaConnect = (void*)GetProcAddress(ws2, "WSAConnect");

    if (MH_Initialize() != MH_OK) { log::line("[hook] MH_Initialize failed"); return false; }

    bool ok = enable("connect", pConnect, (void*)hookConnect, (void**)&realConnect);
    ok &= enable("WSAConnect", pWsaConnect, (void*)hookWsaConnect, (void**)&realWsaConnect);
    return ok;
}

} // namespace uoa::hook
