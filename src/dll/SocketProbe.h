#pragma once

// Runtime probe: hooks ws2_32 closesocket/shutdown and logs a module-relative backtrace each time the
// client tears down a socket after auth. Tells us WHY the client drops the realmd link right after the
// realm list (a full close vs a half-close, and the calling code path) instead of proceeding to the
// world - the one thing static RE cannot pin through the Lua/sol2 + UE-delegate glue.
namespace uoa::socketprobe {

void install();
void arm();   // start logging (call once the realm list has been served)

} // namespace uoa::socketprobe
