#pragma once
#include <cstdint>

// Hook on the client's a1 (SRP challenge) handler. It captures the identity from the auth object on entry
// and the client's derived 40-byte SRP session key on exit. See AuthProbe.cpp.
namespace uoa::authprobe {

void install();

// The 40-byte SRP session key the client derived for the current login (little-endian), or nullptr until
// the a1 handler has run. Used to build the a3 proof the client expects.
const uint8_t* clientSessionKey();

} // namespace uoa::authprobe
