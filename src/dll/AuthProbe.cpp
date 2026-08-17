// AuthProbe.cpp - hooks the client's a1 (SRP challenge) handler. On the way in it captures the identity
// hash from the auth object (for hat-2 against cmangos); on the way out it captures the 40-byte SRP session
// key the handler just derived, so azrtFinish can build the a3 proof M2 = SHA1(A, M1, K) the client expects
// without reproducing the client's own key derivation. Calls the original unchanged. See Identity.cpp.

#include "AuthProbe.h"
#include "Identity.h"
#include "Offsets.h"
#include "Log.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <MinHook.h>

namespace uoa::authprobe {
namespace {

using Handler = uint64_t (*)(void*, void*, uint64_t, uint64_t);
Handler g_original = nullptr;

uint8_t g_clientK[40] = {};
bool    g_clientKReady = false;

// After the handler runs, the client's SRP session key is the OpenSSL BIGNUM at *(self+0x170): d@+0x00
// (8-byte little-endian limbs), top@+0x08 (limb count). Copy up to 40 little-endian bytes, zero-padded at
// the high end. Object-free so the __try is valid; a bignum with a zero MSB has top<5, hence the pad.
void captureClientKey(void* self) {
    __try {
        uint8_t* bn = *reinterpret_cast<uint8_t**>(reinterpret_cast<uint8_t*>(self) + 0x170);
        if (!bn) return;
        const uint8_t* d = *reinterpret_cast<const uint8_t* const*>(bn + 0x00);
        int top = *reinterpret_cast<const int*>(bn + 0x08);
        if (!d || top <= 0) return;
        size_t n = static_cast<size_t>(top) * 8;
        if (n > 40) n = 40;
        uint8_t tmp[40] = {};
        memcpy(tmp, d, n);
        memcpy(g_clientK, tmp, 40);
        g_clientKReady = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

uint64_t detour(void* self, void* packet, uint64_t a3, uint64_t a4) {
    identity::captureFrom(self);
    uint64_t ret = g_original(self, packet, a3, a4);
    captureClientKey(self);   // the handler has now derived K into *(self+0x170)
    return ret;
}

} // namespace

const uint8_t* clientSessionKey() { return g_clientKReady ? g_clientK : nullptr; }

void install() {
    void* target = (void*)((uintptr_t)GetModuleHandleA(nullptr) + off::kA1Handler);
    bool ok = MH_CreateHook(target, (void*)detour, (void**)&g_original) == MH_OK
           && MH_EnableHook(target) == MH_OK;
    log::line(ok ? "[id] identity hook installed" : "[id] identity hook FAILED");
}

} // namespace uoa::authprobe
