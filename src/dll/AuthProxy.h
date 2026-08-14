#pragma once
#include <winsock2.h>

namespace uoa::auth {

// Handles one client auth connection: translates the client's SRP dialect to realmd,
// recomputes the version crc_hash, and rewrites the realmlist so the client reconnects
// through the world proxy.
void handleSession(SOCKET client);

} // namespace uoa::auth
