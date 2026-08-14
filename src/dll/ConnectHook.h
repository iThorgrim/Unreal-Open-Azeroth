#pragma once
#include <winsock2.h>

// Redirects the client's realmd/world connections to the local proxies.
namespace uoa::hook {

using ConnectFn = int (WSAAPI*)(SOCKET, const sockaddr*, int);

extern ConnectFn realConnect;   // trampoline to the real connect; null until install()

bool install();

} // namespace uoa::hook
