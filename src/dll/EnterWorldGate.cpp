// EnterWorldGate.cpp - static byte-patches that let the AZRT auth -> realm -> char flow proceed. Each
// site is byte-verified before writing, so a client update that shifts it is skipped, not miswritten.
// RVAs come from the signature-resolved registry (Offsets.h); re-run resolve_offsets.py after an update:
//   kDiscGate   realmd disconnect gate  -> jne becomes jmp (disconnect unreachable)
//   kFlagJne    a6-reply flag jne       -> nop'd, forcing the flag==0 key-install path
//   kTeardown   per-frame conn teardown -> ret (no-op, so the world conn survives)
// The realm-select readiness predicate (kReadiness) is left unpatched: the real a8 key-install advances
// the channel, and forcing readiness true makes the UI read realm data from a not-yet-populated slot.

#include "EnterWorldGate.h"
#include "Offsets.h"
#include "Log.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstring>

namespace uoa::enterworld {
namespace {

// The realmd connection state-tick tears the socket down whenever it is armed (conn[0x5c]&2) and its
// secure-channel state (conn[0x5d]&0x18) still reads 0x10 = "handshake not established" - which our
// a5/a6/a7/a8 bypass never advances. The gate is a single `jne` (75 09) skipping the disconnect vcall;
// flipping it to an unconditional `jmp` (EB 09) makes the disconnect unreachable, so the connection
// survives for the world handoff.
const uint8_t kFrom = 0x75, kTo = 0xEB;

// Force the a6-reply flag to 0 (the key-install path). The flag is a socket byte our synthetic a6-reply
// doesn't deliver cleanly, so NOP the `jne` that branches on a non-zero flag.
const uint8_t kFlagFrom[2] = { 0x0F, 0x85 };     // jne rel32
const uint8_t kNop6[6]     = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };

// Neutralize the per-frame teardown that kills the fresh world conn before it is used: a bare `ret` at
// its entry makes it a no-op (its first byte is a 0x40 REX prefix). The guard skips the patch unless the
// entry byte matches, so a client that relocates this function is left untouched rather than corrupted.
const uint8_t kTeardownFrom = 0x40, kRet = 0xC3;

bool patch(uintptr_t rva, const void* bytes, size_t n, const char* what) {
    uint8_t* p = (uint8_t*)((uintptr_t)GetModuleHandleA(nullptr) + rva);
    DWORD old;
    if (!VirtualProtect(p, n, PAGE_EXECUTE_READWRITE, &old)) { log::line("[gate] %s FAILED (protect)", what); return false; }
    memcpy(p, bytes, n);
    VirtualProtect(p, n, old, &old);
    FlushInstructionCache(GetCurrentProcess(), p, n);
    log::line("[gate] %s patched", what);
    return true;
}

} // namespace

void install() {
    // Byte-verify each site before patching (guards against an updated client shifting it).
    uint8_t* base = (uint8_t*)GetModuleHandleA(nullptr);

    uint8_t* g = base + off::kDiscGate;
    if (*g == kFrom) patch(off::kDiscGate, &kTo, 1, "realmd disconnect gate (jne->jmp)");
    else             log::line("[gate] disconnect gate mismatch (got 0x%02X, want 0x%02X) - NOT patched", *g, kFrom);

    uint8_t* fj = base + off::kFlagJne;
    if (fj[0] == kFlagFrom[0] && fj[1] == kFlagFrom[1]) patch(off::kFlagJne, kNop6, sizeof kNop6, "a6-reply flag -> 0 (jne nop'd)");
    else log::line("[gate] flag jne mismatch (got 0x%02X 0x%02X) - NOT patched", fj[0], fj[1]);

    uint8_t* td = base + off::kTeardown;
    if (*td == kTeardownFrom) patch(off::kTeardown, &kRet, 1, "world-conn teardown -> ret");
    else log::line("[gate] teardown mismatch (got 0x%02X, want 0x%02X) - NOT patched", *td, kTeardownFrom);
}

} // namespace uoa::enterworld
