#include "Net.h"
#include "ConnectHook.h"

#define WIN32_LEAN_AND_MEAN
#include <ws2tcpip.h>
#include <windows.h>
#include <cstdio>

namespace uoa::net {

int recvExact(SOCKET s, uint8_t* buf, int len) {
    int got = 0;
    while (got < len) {
        int r = recv(s, reinterpret_cast<char*>(buf) + got, len - got, 0);
        if (r <= 0) break;
        got += r;
    }
    return got;
}

bool sendAll(SOCKET s, const uint8_t* buf, int len) {
    int sent = 0;
    while (sent < len) {
        int r = send(s, reinterpret_cast<const char*>(buf) + sent, len - sent, 0);
        if (r <= 0) return false;
        sent += r;
    }
    return true;
}

SOCKET dial(const char* host, uint16_t port) {
    char service[8];
    snprintf(service, sizeof service, "%u", port);

    addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* res = nullptr;
    if (getaddrinfo(host, service, &hints, &res) != 0 || !res)
        return INVALID_SOCKET;

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    // Call the real connect (trampoline) so our own dials are not redirected back to us.
    hook::ConnectFn realConnect = hook::realConnect ? hook::realConnect
                                                    : reinterpret_cast<hook::ConnectFn>(connect);
    int rc = realConnect(s, res->ai_addr, static_cast<int>(res->ai_addrlen));
    freeaddrinfo(res);

    if (rc != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

} // namespace uoa::net
