#include "WorldProxy.h"
#include "WorldPipe.h"
#include "OpcodeMap.h"
#include "Net.h"
#include "Settings.h"
#include "Config.h"
#include "Log.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>

namespace uoa::world {
namespace {

struct Pump { SOCKET from; Pipe* pipe; };

DWORD WINAPI pumpThread(LPVOID param) {
    Pump* p = (Pump*)param;
    uint8_t buf[8192];
    for (;;) {
        int n = recv(p->from, (char*)buf, sizeof buf, 0);
        if (n <= 0) break;
        p->pipe->feed(buf, n);
    }
    return 0;
}

} // namespace

void handleSession(SOCKET client) {
    SOCKET mangosd = net::dial(settings().forwardHost.c_str(), config::kWorldPort);
    if (mangosd == INVALID_SOCKET) {
        log::line("[world] mangosd unreachable");
        closesocket(client);
        return;
    }
    log::line("[world] session (translate)");

    // Two translating pipes, each with its own crypt state, keyed per direction (a8 world key toward the
    // client, cmangos K toward mangos). The shared bridge carries the auth seed from the server->client
    // challenge to the client->server digest rewrite. Bodies pass through unchanged - the client is
    // vanilla-wire, only its opcode numbers are renumbered.
    AuthBridge bridge;
    Pipe toServer(mangosd, 6, mapClientOpcode, "[world] C->S", &bridge);   // client -> mangos
    Pipe toClient(client,  4, mapServerOpcode, "[world] S->C", &bridge);   // mangos -> client

    Pump down{ mangosd, &toClient };
    HANDLE thread = CreateThread(nullptr, 0, pumpThread, &down, 0, nullptr);

    uint8_t buf[8192];
    for (;;) {
        int n = recv(client, (char*)buf, sizeof buf, 0);
        if (n <= 0) break;
        toServer.feed(buf, n);
    }

    closesocket(client);
    closesocket(mangosd);
    if (thread) { WaitForSingleObject(thread, INFINITE); CloseHandle(thread); }
}

} // namespace uoa::world
