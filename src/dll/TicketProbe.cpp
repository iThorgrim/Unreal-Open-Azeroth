#include "TicketProbe.h"
#include "Offsets.h"
#include "Log.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <MinHook.h>

// AZ-TICKET-v1 KDF field fix. The KDF hashes two session string members at +0xA8 and +0xC0. Our
// synthetic a0..a5 shortcut never fills them, so the KDF reads garbage FString headers and faults in
// its serializer. We point both at valid 16-byte buffers on the way in, so the derivation completes.
// Their content is arbitrary - both endpoints of the channel are ours.

namespace uoa::ticketprobe {
namespace {

using Kdf = uint64_t (*)(void*, void*, void*, void*, uint64_t, uint64_t);   // rdx = session + 0xA8
Kdf     g_original = nullptr;
uint8_t g_bufC0[16];
uint8_t g_bufA8[16];

// Write a UE FString header {Data, Num, Max} at `slot`, pointing at a 16-byte buffer.
void setField(uint8_t* slot, uint8_t* buf) {
    *(uint8_t**)(slot)       = buf;
    *(uint32_t*)(slot + 8)   = 16;
    *(uint32_t*)(slot + 0xC) = 16;
}

uint64_t detour(void* rcx, void* rdx, void* r8, void* r9, uint64_t s5, uint64_t s6) {
    __try {
        uint8_t* session = (uint8_t*)rdx - 0xA8;
        setField(session + 0xC0, g_bufC0);
        setField(session + 0xA8, g_bufA8);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return g_original(rcx, rdx, r8, r9, s5, s6);
}

} // namespace

void install() {
    memset(g_bufC0, 0xC0, sizeof g_bufC0);
    memset(g_bufA8, 0xA8, sizeof g_bufA8);
    void* target = (void*)((uintptr_t)GetModuleHandleA(nullptr) + off::kKdf);
    bool ok = MH_CreateHook(target, (void*)detour, (void**)&g_original) == MH_OK
           && MH_EnableHook(target) == MH_OK;
    log::line(ok ? "[kdf] KDF field fix installed" : "[kdf] KDF field fix FAILED");
}

} // namespace uoa::ticketprobe
