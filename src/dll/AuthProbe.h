#pragma once

// Observational hook on the client's a1 (SRP challenge) handler. Read-only: logs the
// incoming challenge and the handler's return value, then calls the original. See
// AuthProbe.cpp - it tells us whether the client rejects the challenge internally.
namespace uoa::authprobe {

void install();

} // namespace uoa::authprobe
