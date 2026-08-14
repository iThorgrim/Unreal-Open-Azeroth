#pragma once
#include <cstdint>

// Thread-safe append log written next to the client.
namespace uoa::log {

void init();
void line(const char* fmt, ...);
void hex(const char* tag, const uint8_t* data, int len);

} // namespace uoa::log
