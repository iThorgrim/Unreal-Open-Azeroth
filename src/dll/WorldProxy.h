#pragma once
#include <winsock2.h>

namespace uoa::world {

// Bridges one client world connection to mangosd, logging both directions.
void handleSession(SOCKET client);

} // namespace uoa::world
