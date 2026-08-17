#pragma once

// Neutralizes the realm-select readiness gate so the client's ChangeRealm path proceeds. The readiness
// predicate normally returns [[realmdconn+0x48]+0x40] (a "secure channel ready" flag only the real
// handlers set); we force it to 1 so realm-select emits its handoff request over the still-open realmd
// socket, which we can then read (plaintext) and answer. Its RVA comes from the resolved registry
// (Offsets.h kReadiness). The disconnect-gate, flag-jne and teardown patches here become unnecessary
// once the auth flow sends a real a8 (key install + channel state 5) rather than faking that state.
namespace uoa::enterworld {

void install();

} // namespace uoa::enterworld
