#pragma once
#include <cstdint>
#include <vector>
#include <winsock2.h>
#include "WorldCipher.h"

namespace uoa::world {

// One direction of the world stream: frames packets, remaps opcodes, re-encrypts, and forwards
// to `out`. Dropped opcodes (remap returns -1) are suppressed. The first packet of each side is
// plaintext (the auth handshake) and forwarded unchanged.
//
// A packet's body may also be rewritten: mangos speaks the vanilla 1.12 wire format, but this
// client is a UE reimplementation whose bodies differ (e.g. TArray counts are int32, not u8).
// When `wants(opcode)` is set for a packet, its whole body is buffered and handed to `apply`,
// which transforms it in place; the header size is recomputed from the new body length.
class Pipe {
public:
    using Remap        = int (*)(int opcode);                           // opcode -> opcode, or -1 to drop
    using WantRewrite  = bool (*)(int opcode);                          // buffer this body for rewriting?
    using ApplyRewrite = void (*)(int opcode, std::vector<uint8_t>&);   // transform a buffered body in place

    Pipe(SOCKET out, int headerLen, Remap remap, const char* tag,
         WantRewrite wants = nullptr, ApplyRewrite apply = nullptr);
    void feed(const uint8_t* data, int len);

private:
    void parse();
    void flushRewritten(int opcode);   // transform a buffered body and emit it (one packet, or a sweep)
    void emitPacket(int opcode);       // send the current bodyBuf_ under one opcode, re-encrypted

    SOCKET       out_;
    int          headerLen_;
    int          bodyAdjust_;   // cmd bytes in the header: 6-byte header -> 4, 4-byte header -> 2
    Remap        remap_;
    const char*  tag_;
    WantRewrite  wants_;
    ApplyRewrite apply_;
    bool         cryptActive_   = false;
    bool         inBody_        = false;
    bool         forwardBody_   = true;
    bool         buffering_     = false;   // collecting a full body to rewrite before forwarding
    int          bodyRemaining_ = 0;
    int          logOpcode_     = 0;       // original opcode of the packet whose body we are accumulating
    int          rewriteOpcode_ = 0;       // opcode to stamp on a rewritten packet (post-remap)
    HeaderCipher recv_;
    HeaderCipher send_;
    std::vector<uint8_t> buf_;
    std::vector<uint8_t> bodyBuf_;   // body of the current packet (full when buffering, capped when logging)
};

} // namespace uoa::world
