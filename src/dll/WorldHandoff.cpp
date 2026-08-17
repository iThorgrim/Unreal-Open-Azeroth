#include "WorldHandoff.h"
#include "AuthProxy.h"
#include "Offsets.h"
#include "Config.h"
#include "Settings.h"
#include "Log.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <MinHook.h>

namespace uoa::worldhandoff {
namespace {

// FName find type: 1 = add the name if it is not already interned, matching the native login pump's call.
constexpr int kFNameAdd = 1;

constexpr uintptr_t kSubsysLoginController = 0xf0;  // subsystem -> login controller (W)
constexpr uintptr_t kCtrlRealmName         = 0x08;  // controller -> committed realm display-name object (arg3)
constexpr uintptr_t kNameWrapperCount      = 0x08;  // name wrapper {obj@+0, count@+8}; count 0 = uncommitted

// arg2's copy-constructor reads an FString as {data ptr, ArrayNum, ArrayMax} and copies exactly ArrayNum
// wide chars; ArrayNum counts the null terminator, ArrayMax is unread here.
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

        auto* controller = *(uint8_t**)((uint8_t*)subsystem + kSubsysLoginController);
        if (!controller) return;
        void* nameObj = controller + kCtrlRealmName;   // arg3: display-name wrapper {obj, count}

        if (*(int32_t*)((uint8_t*)nameObj + kNameWrapperCount) == 0) return;

        // arg2 is our world-proxy destination, not a client-memory field: host from realmlist.wtf, port the
        // connect hook redirects to the world proxy. Built as an FString the copy-constructor accepts.
        wchar_t addrBuf[128];
        int addrLen = swprintf(addrBuf, 128, L"%hs:%hu",
                               settings().forwardHost.c_str(), (unsigned short)config::kWorldPort);
        if (addrLen <= 0) return;
        FStringView addr{ addrBuf, addrLen + 1, addrLen + 1 };   // ArrayNum counts the null terminator

        g_fired = true;   // latch before the call so a re-entrant pump cannot fire the handoff twice
        log::line("[handoff] forcing world login: addr=%ls", addrBuf);
        ((LoginToWorldFn)(base + off::kLoginToWorld))(subsystem, &addr, nameObj);
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
