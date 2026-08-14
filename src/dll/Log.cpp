#include "Log.h"
#include "Config.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdarg>
#include <string>

namespace uoa::log {

static CRITICAL_SECTION g_lock;

void init() {
    InitializeCriticalSection(&g_lock);
}

void line(const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);

    EnterCriticalSection(&g_lock);
    if (FILE* f = fopen(config::kLogFile, "a")) {
        fputs(buf, f);
        fputc('\n', f);
        fclose(f);
    }
    LeaveCriticalSection(&g_lock);
}

void hex(const char* tag, const uint8_t* data, int len) {
    std::string s = tag;
    s += " (" + std::to_string(len) + ")";

    char byte[8];
    for (int i = 0; i < len; ++i) {
        snprintf(byte, sizeof byte, " %02x", data[i]);
        s += byte;
    }
    line("%s", s.c_str());
}

} // namespace uoa::log
