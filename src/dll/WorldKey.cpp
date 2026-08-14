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

const uint8_t kSigImm[]  = { 0xC7, 0x46, 0x70, 0x00, 0x00, 0x00, 0x00, 0xC6, 0x46, 0x74, 0x01 };
const uint8_t kSigR14[]  = { 0x44, 0x89, 0x76, 0x70, 0xC6, 0x46, 0x74, 0x01 };
const uint8_t kSigFlag[] = { 0xC6, 0x46, 0x74, 0x01 };

uint8_t* scanCode(HMODULE mod, IMAGE_NT_HEADERS64* nt, const uint8_t* pat, size_t len, int* count) {
    uint8_t* first = nullptr;
    int found = 0;
    auto sections = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (!(sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        uint8_t* base = (uint8_t*)mod + sections[i].VirtualAddress;
        size_t   size = sections[i].Misc.VirtualSize;
        for (size_t off = 0; off + len <= size; ++off) {
            if (memcmp(base + off, pat, len) == 0) {
                if (!first) first = base + off;
                ++found;
            }
        }
    }
    *count = found;
    return first;
}

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

    struct Signature { const uint8_t* bytes; size_t len; const char* name; };
    const Signature sigs[] = {
        { kSigImm,  sizeof kSigImm,  "imm"  },
        { kSigR14,  sizeof kSigR14,  "r14d" },
        { kSigFlag, sizeof kSigFlag, "flag" },
    };

    uint8_t* target = nullptr;
    for (const Signature& s : sigs) {
        int count = 0;
        uint8_t* hit = scanCode(mod, nt, s.bytes, s.len, &count);
        log::line("[worldkey] sig(%s) matches=%d first=%p", s.name, count, (void*)hit);
        if (count == 1) { target = hit; break; }
    }
    if (!target) { log::line("[worldkey] enable site not found -> hook skipped"); return; }

    bool ok = MH_CreateHook(target, (void*)uoa_worldkey_stub, &uoa_worldkey_trampoline) == MH_OK && MH_EnableHook(target) == MH_OK;
    if (ok) log::line("[worldkey] capture hook installed @ %p", (void*)target);
    else    log::line("[worldkey] capture hook failed @ %p", (void*)target);
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
