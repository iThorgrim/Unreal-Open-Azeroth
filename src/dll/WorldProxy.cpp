#include "WorldProxy.h"
#include "WorldStream.h"
#include "Net.h"
#include "Settings.h"
#include "Config.h"
#include "Log.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>

namespace uoa::world {
namespace {

struct Pipe { SOCKET from; SOCKET to; Stream* stream; };

// Forwards bytes one way unchanged, feeding a copy to the stream parser for opcode logging.
void pump(SOCKET from, SOCKET to, Stream& stream) {
    uint8_t buf[8192];
    for (;;) {
        int n = recv(from, (char*)buf, sizeof buf, 0);
        if (n <= 0) break;
        stream.feed(buf, n);
        net::sendAll(to, buf, n);
    }
}

DWORD WINAPI serverToClient(LPVOID param) {
    Pipe* pipe = (Pipe*)param;
    pump(pipe->from, pipe->to, *pipe->stream);
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

    Stream toServer(Stream::ClientToServer, "[world] C->S");
    Stream toClient(Stream::ServerToClient, "[world] S->C");

    Pipe down{ mangosd, client, &toClient };
    HANDLE thread = CreateThread(nullptr, 0, serverToClient, &down, 0, nullptr);
    pump(client, mangosd, toServer);

    // Close both sockets to unblock the other pump, then wait for it to finish.
    closesocket(client);
    closesocket(mangosd);
    if (thread) { WaitForSingleObject(thread, INFINITE); CloseHandle(thread); }
}

} // namespace uoa::world
