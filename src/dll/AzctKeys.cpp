#include "AzctKeys.h"
#include "AzctCanary.h"
#include "Log.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstring>

namespace uoa::azct {
namespace {

// Overwrite the client's encrypted canary at `rva` with our re-encryption of the same code, so its
// AES-256-CTR validator decrypts it correctly under our key and the CRC still matches.
void patchCanary(uint32_t rva, const uint8_t* enc, uint32_t len, const char* what) {
    uint8_t* region = (uint8_t*)((uintptr_t)GetModuleHandleA(nullptr) + rva);
    DWORD old;
    if (!VirtualProtect(region, len, PAGE_EXECUTE_READWRITE, &old)) { log::line("[azct] %s protect FAILED", what); return; }
    memcpy(region, enc, len);
    VirtualProtect(region, len, old, &old);
    FlushInstructionCache(GetCurrentProcess(), region, len);
    log::line("[azct] %s re-keyed (%u bytes @ 0x%x)", what, len, rva);
}

} // namespace

void install() {
    patchCanary(kSlot0Rva, kSlot0Enc, kSlot0Len, "slot0 a1/integrity");
    // slot1 (CHAR_ENUM) is patched when the char-list push is wired; the header already carries it.
}

} // namespace uoa::azct
