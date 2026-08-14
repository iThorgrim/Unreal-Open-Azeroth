#include "WorldKey.h"
#include "Log.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstring>
#include <MinHook.h>

// Defined in WorldKeyStub.asm.
extern "C" void  uoa_worldkey_stub();
extern "C" void* uoa_worldkey_trampoline = nullptr;

namespace uoa::worldkey {
namespace {

uint8_t g_key[64];
int     g_length = 0;
bool    g_ready  = false;

// Crypt-enable site (the only "[obj+0x74]=1" store). At this point RSI = WorldSession,
// with the key pointer at +0x60 and its length at +0x68. Value is at the PE preferred base.
const uint64_t kEnableVA = 0x14412c4b3;

} // namespace

bool           ready()  { return g_ready; }
const uint8_t* key()    { return g_ready ? g_key : nullptr; }
int            length() { return g_length; }

// Called from the asm stub with the WorldSession pointer.
static void store(const uint8_t* keyPtr, int len) {
    if (g_ready) return;
    memcpy(g_key, keyPtr, len);
    g_length = len;
    g_ready  = true;
    log::hex("[worldkey] K", g_key, len);
}

void install() {
    HMODULE mod = GetModuleHandleA(nullptr);
    auto dos = (IMAGE_DOS_HEADER*)mod;
    auto nt  = (IMAGE_NT_HEADERS64*)((uint8_t*)mod + dos->e_lfanew);
    uint64_t imageBase = nt->OptionalHeader.ImageBase;

    void* target = (void*)((uintptr_t)mod + (uintptr_t)(kEnableVA - imageBase));
    log::line("[worldkey] base=%p enable=%p", (void*)mod, target);

    bool ok = MH_CreateHook(target, (void*)uoa_worldkey_stub, &uoa_worldkey_trampoline) == MH_OK && MH_EnableHook(target) == MH_OK;
    log::line(ok ? "[worldkey] capture hook installed" : "[worldkey] capture hook failed");
}

} // namespace uoa::worldkey

// C entry point invoked by the stub. Reads K from the WorldSession object.
extern "C" void uoa_worldkey_capture(void* session) {
    if (uoa::worldkey::ready() || !session) return;
    __try {
        uint8_t* base   = (uint8_t*)session;
        uint8_t* keyPtr = *(uint8_t**)(base + 0x60);
        uint32_t keyLen = *(uint32_t*)(base + 0x68);
        if (keyPtr && keyLen >= 16 && keyLen <= 64)
            uoa::worldkey::store(keyPtr, (int)keyLen);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}
