#include "DiscordPresence.h"
#include "Settings.h"
#include "Log.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <MinHook.h>

namespace uoa::discord {
namespace {

// Discord Social SDK C ABI.
struct DiscordString { const uint8_t* ptr; size_t size; };
using SetStr = void (*)(void* activity, DiscordString* value);
using SetI32 = void (*)(void* activity, int32_t value);
using SetU64 = void (*)(void* activity, uint64_t value);

SetStr realSetDetails = nullptr;
SetStr realSetState   = nullptr;
SetI32 realSetType    = nullptr;
SetU64 realSetAppId   = nullptr;

DiscordString g_details{};   // stable views over the configured strings
DiscordString g_state{};

// The activity's application_id drives the displayed title, so we set it on the same
// activity the game builds. This changes the title without touching the client's auth.
void injectAppId(void* activity) {
    const Settings& s = settings();
    if (s.hasAppId && realSetAppId) realSetAppId(activity, s.appId);
}

void hookSetDetails(void* a, DiscordString* v) { injectAppId(a); realSetDetails(a, settings().hasDetails ? &g_details : v); }
void hookSetState(void* a, DiscordString* v)   { injectAppId(a); realSetState(a, settings().hasState ? &g_state : v); }
void hookSetType(void* a, int32_t t)           { realSetType(a, settings().hasType ? settings().type : t); }
void hookSetAppId(void* a, uint64_t id)        { realSetAppId(a, settings().hasAppId ? settings().appId : id); }

bool hookProc(HMODULE mod, const char* name, void* detour, void** trampoline) {
    void* target = (void*)GetProcAddress(mod, name);
    return target && MH_CreateHook(target, detour, trampoline) == MH_OK && MH_EnableHook(target) == MH_OK;
}

DWORD WINAPI worker(LPVOID) {
    HMODULE mod = nullptr;
    for (int i = 0; i < 240 && !mod; ++i) {
        mod = GetModuleHandleA("discord_partner_sdk.dll");
        if (!mod) Sleep(250);
    }
    if (!mod) { log::line("[discord] discord_partner_sdk.dll absent -> presence hook skipped"); return 0; }

    const Settings& s = settings();
    g_details = { (const uint8_t*)s.details.c_str(), s.details.size() };
    g_state   = { (const uint8_t*)s.state.c_str(), s.state.size() };

    int ok = 0;
    ok += hookProc(mod, "Discord_Activity_SetDetails", (void*)hookSetDetails, (void**)&realSetDetails);
    ok += hookProc(mod, "Discord_Activity_SetState", (void*)hookSetState, (void**)&realSetState);
    ok += hookProc(mod, "Discord_Activity_SetType", (void*)hookSetType, (void**)&realSetType);
    if (s.hasAppId) ok += hookProc(mod, "Discord_Activity_SetApplicationId", (void*)hookSetAppId, (void**)&realSetAppId);

    log::line("[discord] presence hooks installed (%d/%d)", ok, s.hasAppId ? 4 : 3);
    return 0;
}

} // namespace

void installAsync() {
    CreateThread(nullptr, 0, worker, nullptr, 0, nullptr);
}

} // namespace uoa::discord
