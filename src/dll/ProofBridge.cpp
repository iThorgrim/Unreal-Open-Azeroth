#include "ProofBridge.h"
#include "Offsets.h"
#include "AzctCanary.h"
#include "Log.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>     // _ReturnAddress
#include <cstdint>
#include <cstring>
#include <MinHook.h>

namespace uoa::proof {
namespace {

// The a3 proof-verify lives inside the AZCT slot-0 canary; its `call` to the digest finalizer returns
// at a fixed 0x9e into that canary, so the caller RVA tracks the canary base across client builds.
constexpr uintptr_t kCallerRva = azct::kSlot0Rva + 0x9e;

using Fn = void* (*)(void*, void*, void*, void*);   // pass all 4 regs through for unrelated callers
Fn      g_orig   = nullptr;
uint8_t g_m2[20] = {};
bool    g_haveM2 = false;

void* detour(void* rcx, void* rdx, void* r8, void* r9) {
    void* caller = _ReturnAddress();
    void* ret = g_orig(rcx, rdx, r8, r9);
    // Only for the proof-verify's own call site: overwrite the computed digest (in rcx) with our sent M2,
    // so the client's compare-to-our-M2 succeeds and it runs its auth-complete path.
    if (g_haveM2 && caller == (void*)((uintptr_t)GetModuleHandleA(nullptr) + kCallerRva))
        __try { memcpy(rcx, g_m2, 20); } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return ret;
}

} // namespace

void setSentM2(const uint8_t m2[20]) { memcpy(g_m2, m2, 20); g_haveM2 = true; }

void install() {
    void* target = (void*)((uintptr_t)GetModuleHandleA(nullptr) + off::kFinalize);
    bool ok = MH_CreateHook(target, (void*)detour, (void**)&g_orig) == MH_OK
           && MH_EnableHook(target) == MH_OK;
    log::line(ok ? "[proof] a3 proof-verify bridge installed" : "[proof] proof bridge FAILED");
}

} // namespace uoa::proof
