#pragma once
#include <cstdint>
#include <winsock2.h>

namespace uoa::net {

int    recvExact(SOCKET s, uint8_t* buf, int len);   // read exactly len bytes (or fewer on close)
bool   sendAll(SOCKET s, const uint8_t* buf, int len);
SOCKET dial(const char* host, uint16_t port);        // outbound; bypasses our own connect hook

} // namespace uoa::net
