#include "CrashProbe.h"
#include "Log.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>

namespace uoa::crashprobe {
namespace {

volatile long g_logged = 0;

// Log a return address that falls inside the main module, to sketch a mini call stack.
void logFrame(const char* tag, uintptr_t addr, uintptr_t base, uintptr_t size) {
    if (addr >= base && addr < base + size)
        log::line("%s %p (rva 0x%llX)", tag, (void*)addr, (unsigned long long)(addr - base));
}

LONG CALLBACK handler(PEXCEPTION_POINTERS info) {
    const DWORD code = info->ExceptionRecord->ExceptionCode;
    if (code != EXCEPTION_ACCESS_VIOLATION && code != EXCEPTION_ILLEGAL_INSTRUCTION
        && code != EXCEPTION_PRIV_INSTRUCTION)
        return EXCEPTION_CONTINUE_SEARCH;

    if (InterlockedIncrement(&g_logged) > 6) return EXCEPTION_CONTINUE_SEARCH;

    uintptr_t base = (uintptr_t)GetModuleHandleA(nullptr);
    uintptr_t size = 0;
    if (auto* dos = (IMAGE_DOS_HEADER*)base) {
        auto* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        size = nt->OptionalHeader.SizeOfImage;
    }

    auto* rec = info->ExceptionRecord;
    uintptr_t rip = (uintptr_t)rec->ExceptionAddress;
    log::line("[crash] code=0x%08lX at %p (rva 0x%llX) tid=%lu", code, (void*)rip,
              (unsigned long long)(rip >= base ? rip - base : 0), GetCurrentThreadId());
    if (code == EXCEPTION_ACCESS_VIOLATION && rec->NumberParameters >= 2) {
        const char* op = rec->ExceptionInformation[0] == 1 ? "write"
                       : rec->ExceptionInformation[0] == 8 ? "exec" : "read";
        log::line("[crash]   %s addr=%p", op, (void*)rec->ExceptionInformation[1]);
    }

    // Registers at fault: for an allocator crash R8/R9 carry the (garbage) size/count and RCX/RDX the
    // source pointer, which usually points straight back at the malformed length we fed in.
    auto* ctx = info->ContextRecord;
    log::line("[crash]   rcx=%016llX rdx=%016llX r8=%016llX r9=%016llX",
              (unsigned long long)ctx->Rcx, (unsigned long long)ctx->Rdx,
              (unsigned long long)ctx->R8, (unsigned long long)ctx->R9);
    log::line("[crash]   rbx=%016llX rsi=%016llX rdi=%016llX rbp=%016llX",
              (unsigned long long)ctx->Rbx, (unsigned long long)ctx->Rsi,
              (unsigned long long)ctx->Rdi, (unsigned long long)ctx->Rbp);

    // Walk the stack for return addresses inside the module (rough backtrace), skipping repeats so the
    // deeper auth-handler frame (0x14412xxxx range) is not buried under duplicate allocator frames.
    logFrame("[crash]   rip", rip, base, size);
    __try {
        uintptr_t* sp = (uintptr_t*)ctx->Rsp;
        uintptr_t prev = 0;
        for (int i = 0; i < 240; ++i) {
            uintptr_t a = sp[i];
            if (a != prev && a >= base && a < base + size) { logFrame("[crash]   ret", a, base, size); prev = a; }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    return EXCEPTION_CONTINUE_SEARCH;   // let the client's own handler still run
}

} // namespace

void install() {
    AddVectoredExceptionHandler(1, handler);   // 1 = first in the chain
    log::line("[crash] vectored handler installed");
}

} // namespace uoa::crashprobe
