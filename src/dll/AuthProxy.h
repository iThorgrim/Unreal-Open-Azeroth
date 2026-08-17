#pragma once
#include <winsock2.h>
#include <atomic>

namespace uoa::auth {

// Raised once our synthetic auth + realm exchange has fully completed for a session: the b1 realm list has
// been sent, which in the AZRT order follows the a8/a9 world-key install. The world handoff waits on this
// authoritative protocol signal instead of inferring readiness from client memory, whose login-controller
// fields are not yet meaningful mid-handshake (they read as set well before a realm is committed).
extern std::atomic<bool> g_realmReady;

// The 40-byte session key K that cmangos stored for this account, obtained by hat-2's real classic SRP6
// against the local realmd. The world proxy needs it to recompute the CMSG_AUTH_SESSION digest and to key
// the mangos-side header cipher: cmangos verifies both against this K, not against the a8 world key the
// client installed. Populated once hat-2 succeeds; sessionKey() is null until then.
extern std::atomic<bool> g_sessionReady;
const uint8_t* sessionKey();     // 40-byte cmangos K, or nullptr while unready
int            sessionKeyLen();  // 40

// Handles one client auth connection: translates the client's SRP dialect to realmd,
// recomputes the version crc_hash, and rewrites the realmlist so the client reconnects
// through the world proxy.
void handleSession(SOCKET client);

} // namespace uoa::auth
