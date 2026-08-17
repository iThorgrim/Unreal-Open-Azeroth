#pragma once
#include <cstdint>
#include <vector>
#include <atomic>
#include <winsock2.h>
#include "WorldCipher.h"

namespace uoa::world {

// Shared between the two pipes of one world session. The server->client pipe latches the u32 seed from
// SMSG_AUTH_CHALLENGE; the client->server pipe folds it into the recomputed CMSG_AUTH_SESSION digest.
// Vanilla ordering guarantees the challenge is forwarded before the client emits its auth session, so the
// write always precedes the cross-thread read.
struct AuthBridge {
    std::atomic<uint32_t> serverSeed{0};
    std::atomic<bool>     seedReady{false};
};

// One direction of the world stream: frames packets, remaps opcodes, re-encrypts, and forwards
// to `out`. Dropped opcodes (remap returns -1) are suppressed. The first packet of each side is
// plaintext (the auth handshake); on that packet the pipe rewrites the CMSG_AUTH_SESSION digest or
// captures the SMSG_AUTH_CHALLENGE seed before forwarding. Bodies are otherwise vanilla-wire and pass
// through unchanged, save two the client shapes differently: SMSG_CHAR_ENUM gains its key trailer and
// CMSG_CHAR_CREATE carries a trailing byte the vanilla server rejects. Both are buffered whole and rebuilt.
class Pipe {
public:
    using Remap = int (*)(int opcode);   // opcode -> opcode, or -1 to drop

    Pipe(SOCKET out, int headerLen, Remap remap, const char* tag, AuthBridge* bridge);
    void feed(const uint8_t* data, int len);

private:
    void parse();
    void bridgePlaintext(uint8_t* pkt, int total, int opcode);   // seed capture / digest rewrite on the pre-crypt packet
    void rewriteAuthSession(uint8_t* pkt, int total);            // recompute the CMSG_AUTH_SESSION digest with cmangos K
    void emitCharEnum();                                         // reshape the buffered char list and forward it
    void emitTrim();                                             // trim a buffered client packet to vanilla length
    void emitGuidQuery();                                        // turn a query-by-guid into the matching vanilla query
    void injectWorldAccess();                                    // emit the world-access grant ahead of LOGIN_VERIFY_WORLD

    SOCKET       out_;
    int          headerLen_;
    int          bodyAdjust_;   // cmd bytes in the header: 6-byte header -> 4, 4-byte header -> 2
    Remap        remap_;
    const char*  tag_;
    bool         fromClient_;   // client->server side: picks the right name for a renumbered opcode
    AuthBridge*  bridge_;
    bool         cryptActive_   = false;
    bool         inBody_        = false;
    bool         forwardBody_   = true;
    bool         xformCharEnum_ = false;   // current body is SMSG_CHAR_ENUM, buffered whole for reshaping
    bool         xformTrim_     = false;   // current body is a padded client packet, buffered whole for trimming
    bool         xformGuidQuery_ = false;  // current body is a query-by-guid, buffered whole to derive the entry
    int          bodyRemaining_ = 0;
    int          logOpcode_     = 0;       // original opcode of the packet whose body we are accumulating
    int          mappedOpcode_  = 0;       // renumbered opcode to stamp on a rebuilt body's header
    HeaderCipher recv_;
    HeaderCipher send_;
    std::vector<uint8_t> buf_;
    std::vector<uint8_t> bodyBuf_;       // capped copy of the current body, for the diagnostic hex dump
    std::vector<uint8_t> xformBody_;     // full body accumulated across reads for a reshape/trim transform
};

} // namespace uoa::world
