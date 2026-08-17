#include "SocketProbe.h"
#include "Log.h"

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <cstdint>
#include <MinHook.h>

namespace uoa::socketprobe {
namespace {

volatile long g_armed  = 0;
volatile long g_logged = 0;

using CloseFn    = int (WINAPI*)(SOCKET);
using ShutdownFn = int (WINAPI*)(SOCKET, int);
CloseFn    g_realClose    = nullptr;
ShutdownFn g_realShutdown = nullptr;

// Walk the stack for return addresses inside the main module (rough backtrace), skipping repeats.
void backtrace(const char* tag, SOCKET s, int how) {
    uintptr_t base = (uintptr_t)GetModuleHandleA(nullptr);
    uintptr_t size = 0;
    if (auto* dos = (IMAGE_DOS_HEADER*)base) {
        auto* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        size = nt->OptionalHeader.SizeOfImage;
    }
    if (how < 0) log::line("%s sock=%llu", tag, (unsigned long long)s);
    else         log::line("%s sock=%llu how=%d", tag, (unsigned long long)s, how);
    void* frames[40];
    USHORT n = RtlCaptureStackBackTrace(1, 40, frames, nullptr);
    int shown = 0;
    for (USHORT i = 0; i < n && shown < 24; ++i) {
        uintptr_t a = (uintptr_t)frames[i];
        if (a >= base && a < base + size) {
            log::line("  ret %p (rva 0x%llX)", frames[i], (unsigned long long)(a - base));
            ++shown;
        }
    }
}

int WINAPI hookClose(SOCKET s) {
    if (InterlockedCompareExchange(&g_armed, 1, 1) && InterlockedIncrement(&g_logged) <= 12)
        backtrace("[sock] closesocket", s, -1);
    return g_realClose(s);
}

int WINAPI hookShutdown(SOCKET s, int how) {
    if (InterlockedCompareExchange(&g_armed, 1, 1) && InterlockedIncrement(&g_logged) <= 12)
        backtrace("[sock] shutdown", s, how);
    return g_realShutdown(s, how);
}

} // namespace

void arm() { InterlockedExchange(&g_armed, 1); log::line("[sock] probe armed"); }

void install() {
    HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
    if (!ws2) ws2 = LoadLibraryA("ws2_32.dll");
    void* pClose    = (void*)GetProcAddress(ws2, "closesocket");
    void* pShutdown = (void*)GetProcAddress(ws2, "shutdown");
    bool ok = MH_CreateHook(pClose, (void*)hookClose, (void**)&g_realClose) == MH_OK
           && MH_EnableHook(pClose) == MH_OK
           && MH_CreateHook(pShutdown, (void*)hookShutdown, (void**)&g_realShutdown) == MH_OK
           && MH_EnableHook(pShutdown) == MH_OK;
    log::line(ok ? "[sock] close/shutdown hooks installed" : "[sock] socket hooks FAILED");
}

} // namespace uoa::socketprobe
