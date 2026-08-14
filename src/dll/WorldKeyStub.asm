; Detour for the crypt-enable site. Reached by a jmp with registers intact, so RSI
; still holds the WorldSession object. We pass it to the C handler, then resume through
; the MinHook trampoline (which runs the overwritten instruction and jumps back).

EXTERN uoa_worldkey_capture    : PROC
EXTERN uoa_worldkey_trampoline : QWORD

PUBLIC uoa_worldkey_stub

.code
uoa_worldkey_stub PROC
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    sub  rsp, 28h
    mov  rcx, rsi
    call uoa_worldkey_capture
    add  rsp, 28h
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    pop  rax
    jmp  qword ptr [uoa_worldkey_trampoline]
uoa_worldkey_stub ENDP
end
