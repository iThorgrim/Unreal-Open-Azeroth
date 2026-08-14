#include "WorldProxy.h"
#include "Net.h"
#include "Settings.h"
#include "Config.h"
#include "Log.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>

namespace uoa::world {
namespace {

struct Pipe { SOCKET from; SOCKET to; const char* tag; };

// Forwards bytes one way, logging up to 64 bytes of each chunk.
void pump(SOCKET from, SOCKET to, const char* tag) {
    uint8_t buf[8192];
    for (;;) {
        int n = recv(from, (char*)buf, sizeof buf, 0);
        if (n <= 0) break;
        log::hex(tag, buf, n > 64 ? 64 : n);
        net::sendAll(to, buf, n);
    }
}

DWORD WINAPI serverToClient(LPVOID param) {
    Pipe* pipe = (Pipe*)param;
    pump(pipe->from, pipe->to, pipe->tag);
    delete pipe;
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
    log::line("[world] session (capture)");

    Pipe* down = new Pipe{ mangosd, client, "[world] S->C" };
    HANDLE thread = CreateThread(nullptr, 0, serverToClient, down, 0, nullptr);
    pump(client, mangosd, "[world] C->S");
    if (thread) { WaitForSingleObject(thread, 2000); CloseHandle(thread); }

    closesocket(client);
    closesocket(mangosd);
}

} // namespace uoa::world
