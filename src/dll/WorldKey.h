#pragma once
#include <cstdint>

// Captures the 40-byte world session key K from the client at runtime.
namespace uoa::worldkey {

bool           ready();
const uint8_t* key();
int            length();
void           install();   // hooks the crypt-enable site (RSI = WorldSession) to grab K

} // namespace uoa::worldkey
