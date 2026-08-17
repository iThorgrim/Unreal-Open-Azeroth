#include "WorldHandoff.h"
#include "AuthProxy.h"
#include "Offsets.h"
#include "Log.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cwchar>
#include <MinHook.h>

namespace uoa::worldhandoff {
namespace {

// The realmd connection hangs off a fixed subsystem member; LoginToWorld reads it to rebuild the world
// channel. Readiness is taken from the auth proxy's protocol state, not from client memory.
constexpr uintptr_t kSubsysRealmdConn = 0x100;   // subsystem -> realmd connection

// FName find type: 1 = add the name if it is not already interned, matching the native login pump's call.
constexpr int kFNameAdd = 1;

// The realm destination the client received in the b1 realm list. It is passed as LoginToWorld's address
// argument, which set-realm feeds into the rebuilt world channel's URL - the field the client actually
// connects through; the connect hook then rewrites this port to the world proxy.
const wchar_t kRealmAddr[] = L"127.0.0.1:8085";

// The client's FString is a TArray<TCHAR>: data pointer, then ArrayNum (element count including the null
// terminator), then ArrayMax. LoginToWorld's address argument is copied by a plain FString copy
// constructor that reads exactly {data, num} and allocates num*sizeof(TCHAR); ArrayMax is unread here.
struct FStringView {
    const wchar_t* data;
    int32_t        num;
    int32_t        max;
};

using FNameCtorFn    = void* (*)(void* outName, const wchar_t* text, int findType);
using GetSubsystemFn = void* (*)(void* collection, void* fnamePtr);
using LoginToWorldFn = void  (*)(void* subsystem, void* addrFStr, void* nameFStr);
using PeekMessageWFn = BOOL  (WINAPI*)(LPMSG, HWND, UINT, UINT, UINT);

PeekMessageWFn g_origPeek = nullptr;
bool           g_fired    = false;

void* resolveSubsystem(uintptr_t base) {
    // Reproduce the native login pump: FName("MANGOS") then GetSubsystem(collection, &name).
    static const wchar_t kMangos[] = L"MANGOS";
    uint64_t name[2] = { 0, 0 };
    ((FNameCtorFn)(base + off::kFNameCtor))(name, kMangos, kFNameAdd);
    void* collection = *(void**)(base + off::kSubsysCollection);
    if (!collection) return nullptr;
    return ((GetSubsystemFn)(base + off::kGetSubsystem))(collection, name);
}

void tryHandoff() {
    uintptr_t base = (uintptr_t)GetModuleHandleA(nullptr);
    __try {
        void* subsystem = resolveSubsystem(base);
        if (!subsystem) return;
        void* realmdConn = *(void**)((uint8_t*)subsystem + kSubsysRealmdConn);
        if (!realmdConn) return;

        int32_t len = (int32_t)(wcslen(kRealmAddr) + 1);   // ArrayNum counts the null terminator
        FStringView addr{ kRealmAddr, len, len };          // address argument -> world channel URL
        // The name argument is copied by a different, type-aware copy that would dereference its data as a
        // reference-counted object with a vtable; a count of 0 makes that copy take its empty path, so we
        // hand it an empty value. set-realm stores it in a field the connect path does not read.
        FStringView name{ nullptr, 0, 0 };
        g_fired = true;   // latch before the call so a re-entrant pump cannot fire the handoff twice
        log::line("[handoff] forcing world login: addr=%ls", kRealmAddr);
        ((LoginToWorldFn)(base + off::kLoginToWorld))(subsystem, &addr, &name);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // A poll landing during subsystem init/teardown can momentarily expose stale pointers; the guard
        // turns that into a skipped frame rather than a crash.
    }
}

BOOL WINAPI hookPeek(LPMSG msg, HWND hwnd, UINT filterMin, UINT filterMax, UINT removeMsg) {
    if (!g_fired && auth::g_realmReady.load()) tryHandoff();
    return g_origPeek(msg, hwnd, filterMin, filterMax, removeMsg);
}

} // namespace

void install() {
    HMODULE user32 = GetModuleHandleA("user32.dll");
    void* target = user32 ? (void*)GetProcAddress(user32, "PeekMessageW") : nullptr;
    bool ok = target
           && MH_CreateHook(target, (void*)hookPeek, (void**)&g_origPeek) == MH_OK
           && MH_EnableHook(target) == MH_OK;
    log::line(ok ? "[handoff] world-login trigger armed on PeekMessageW"
                 : "[handoff] PeekMessageW hook FAILED");
}

} // namespace uoa::worldhandoff
