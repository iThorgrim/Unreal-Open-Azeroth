// AuthProbe.cpp - hooks the client's a1 (SRP challenge) handler to capture the identity hash
// I = SHA1(UPPER(user):UPPER(pass)) from the auth object, in-process. Read-only with respect to the
// client: it calls the original unchanged. See Identity.cpp.

#include "AuthProbe.h"
#include "Identity.h"
#include "Offsets.h"
#include "Log.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <MinHook.h>

namespace uoa::authprobe {
namespace {

using Handler = uint64_t (*)(void*, void*, uint64_t, uint64_t);
Handler g_original = nullptr;

uint64_t detour(void* self, void* packet, uint64_t a3, uint64_t a4) {
    identity::captureFrom(self);
    return g_original(self, packet, a3, a4);
}

} // namespace

void install() {
    void* target = (void*)((uintptr_t)GetModuleHandleA(nullptr) + off::kA1Handler);
    bool ok = MH_CreateHook(target, (void*)detour, (void**)&g_original) == MH_OK
           && MH_EnableHook(target) == MH_OK;
    log::line(ok ? "[id] identity hook installed" : "[id] identity hook FAILED");
}

} // namespace uoa::authprobe
