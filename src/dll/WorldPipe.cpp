#include "WorldPipe.h"
#include "OpcodeNames.h"
#include "OpCodes.h"
#include "ByteBuffer.h"
#include "Sha1.h"
#include "AuthProxy.h"
#include "WorldKey.h"
#include "AzctCanary.h"
#include "Net.h"
#include "Log.h"

#include <cstring>
#include <cstdio>
#include <string>

namespace uoa::world {

// Cap the diagnostic body dump so a large packet (world state, char list) stays readable in the log.
static constexpr int kBodyLogCap = 128;

namespace {

constexpr int kTrailerLen = 32;

// The client parses the vanilla 1.12 SMSG_CHAR_ENUM body verbatim and then requires a mandatory 32-byte key
// trailer; the real server for this client appends that trailer to an otherwise untouched vanilla body, so
// we mirror it exactly: forward the body as received and append the char-enum protected-region key. Field
// layout is therefore whatever the backend sent, which is already the wire form the client reads: each
// equipment slot is displayId + inventoryType with no per-slot enchant, 20 slots (19 worn + first bag). We
// re-keyed that region to ours (azct::install), so the client decrypts and CRC-validates the trailer with
// azct::kSlot1Key, and the empty-list case (count 0) still needs the trailer present or the client reports
// the list incomplete.
Bytes reshapeCharEnum(const uint8_t* body, int len) {
    ByteWriter w;
    w.bytes(body, size_t(len));
    w.bytes(azct::kSlot1Key, kTrailerLen);
    return w.take();
}

// Trim a CMSG_CHAR_CREATE body to its exact vanilla 1.12 length. The client appends a trailing byte the
// vanilla server does not read, which makes the server's packet validator reject the size; the vanilla body
// is the name (a null-terminated string) followed by nine appearance/outfit bytes, so we keep name + 9 and
// drop anything past it.
Bytes trimCharCreate(const uint8_t* body, int len) {
    ByteReader r(body, size_t(len));
    r.cstr();                                              // name, read through its terminator
    size_t vanilla = (size_t(len) - r.remaining()) + 9;   // + race, class, gender, skin, face, hairStyle, hairColor, facialHair, outfitId
    if (vanilla > size_t(len)) vanilla = size_t(len);     // a short body is forwarded as-is, never grown
    ByteWriter w;
    w.bytes(body, vanilla);
    return w.take();
}

} // namespace

Pipe::Pipe(SOCKET out, int headerLen, Remap remap, const char* tag, AuthBridge* bridge)
    : out_(out), headerLen_(headerLen), bodyAdjust_(headerLen - 2),
      remap_(remap), tag_(tag), fromClient_(strstr(tag, "C->S") != nullptr), bridge_(bridge) {
    // The two channels advance to header crypt on different keys. recv_ inverts what the sending peer
    // enciphered; send_ enciphers for the receiving peer. Vanilla keys client<->proxy on the a8 world key
    // and proxy<->mangos on cmangos K, so the proxy decrypts under one and re-encrypts under the other.
    if (fromClient_) {
        recv_.useKey(&worldkey::key,   &worldkey::length);       // from the client: a8 world key
        send_.useKey(&auth::sessionKey, &auth::sessionKeyLen);   // to mangos: cmangos K
    } else {
        recv_.useKey(&auth::sessionKey, &auth::sessionKeyLen);   // from mangos: cmangos K
        send_.useKey(&worldkey::key,   &worldkey::length);       // to the client: a8 world key
    }
}

// "0x0037 CMSG_CHAR_ENUM" when the opcode is catalogued, else just "0x0037". Written into a caller
// buffer so it can drop straight into a log format string.
static const char* opLabel(char* buf, size_t n, int op, bool fromClient) {
    const char* nm = op::worldName(op, fromClient);
    if (nm) snprintf(buf, n, "0x%04X %s", op, nm);
    else    snprintf(buf, n, "0x%04X", op);
    return buf;
}

void Pipe::feed(const uint8_t* data, int len) {
    buf_.insert(buf_.end(), data, data + len);
    parse();
}

// Recompute the CMSG_AUTH_SESSION digest so it matches the K cmangos stored for this account. The client
// computed the digest with the a8 world key it installed, which cmangos never saw; only the key differs
// between the two, since account, clientSeed and serverSeed are identical on both ends of the proxy.
void Pipe::rewriteAuthSession(uint8_t* pkt, int total) {
    const uint8_t* K = auth::sessionKey();
    if (!K) { log::line("%s CMSG_AUTH_SESSION: cmangos K unready -> forwarded unchanged", tag_); return; }
    if (!bridge_ || !bridge_->seedReady.load(std::memory_order_acquire)) {
        log::line("%s CMSG_AUTH_SESSION: server seed uncaptured -> forwarded unchanged", tag_);
        return;
    }
    uint32_t serverSeed = bridge_->serverSeed.load(std::memory_order_acquire);

    // 1.12 body: u32 build, u32 serverId, CString account, u32 clientSeed, u8 digest[20].
    const uint8_t* body = pkt + headerLen_;
    int bodyLen = total - headerLen_;
    ByteReader r(body, size_t(bodyLen));
    r.u32();                                 // client build
    r.u32();                                 // server id
    std::string account = r.cstr();
    uint32_t clientSeed = r.u32();

    int digestOff = headerLen_ + 4 + 4 + int(account.size()) + 1 + 4;
    if (digestOff + 20 > total) { log::line("%s CMSG_AUTH_SESSION: truncated body -> not rewritten", tag_); return; }

    // digest = SHA1( account || u32(0) || clientSeed || serverSeed || K[40] ), each u32 little-endian,
    // matching cmangos WorldSocket::HandleAuthSession.
    Sha1 sha;
    uint32_t zero = 0;
    sha.update(reinterpret_cast<const uint8_t*>(account.data()), account.size());
    sha.update(reinterpret_cast<const uint8_t*>(&zero), 4);
    sha.update(reinterpret_cast<const uint8_t*>(&clientSeed), 4);
    sha.update(reinterpret_cast<const uint8_t*>(&serverSeed), 4);
    sha.update(K, 40);
    uint8_t digest[20];
    sha.finish(digest);
    memcpy(pkt + digestOff, digest, 20);
    log::line("%s CMSG_AUTH_SESSION rewritten (account=%s clientSeed=0x%08X serverSeed=0x%08X)",
              tag_, account.c_str(), clientSeed, serverSeed);
}

// The single pre-crypt packet of each side. Server->client: latch the SMSG_AUTH_CHALLENGE seed.
// Client->server: rewrite the CMSG_AUTH_SESSION digest to cmangos K.
void Pipe::bridgePlaintext(uint8_t* pkt, int total, int opcode) {
    if (!fromClient_) {
        if (opcode == op::mangos::kSMSG_AUTH_CHALLENGE && bridge_ && total >= headerLen_ + 4) {
            uint32_t seed;
            memcpy(&seed, pkt + headerLen_, 4);   // body is a single u32 seed
            bridge_->serverSeed.store(seed, std::memory_order_release);
            bridge_->seedReady.store(true, std::memory_order_release);
            log::line("%s captured auth challenge seed 0x%08X", tag_, seed);
        }
        return;
    }
    if (remap_(opcode) == op::mangos::kCMSG_AUTH_SESSION) rewriteAuthSession(pkt, total);
}

void Pipe::parse() {
    for (;;) {
        if (!cryptActive_) {
            // Pre-crypt: exactly one plaintext packet per side (the world auth handshake). Buffer it whole
            // so the digest can be rewritten / the seed captured in place before it is forwarded. These
            // packets are tiny, so full buffering costs nothing.
            if ((int)buf_.size() < headerLen_) return;

            int size   = (buf_[0] << 8) | buf_[1];
            int opcode = buf_[2] | (buf_[3] << 8);
            int bodyLen = size - bodyAdjust_;
            if (bodyLen < 0) bodyLen = 0;
            int total = headerLen_ + bodyLen;
            if ((int)buf_.size() < total) return;   // hold until the whole plaintext packet is present

            uint8_t* pkt = buf_.data();
            bridgePlaintext(pkt, total, opcode);

            char lbl[64];
            log::line("%s op=%s size=%d (plain)", tag_, opLabel(lbl, sizeof lbl, opcode, fromClient_), size);
            net::sendAll(out_, pkt, total);

            char blbl[96];
            int keep = bodyLen < kBodyLogCap ? bodyLen : kBodyLogCap;
            snprintf(blbl, sizeof blbl, "%s body %s", tag_, opLabel(lbl, sizeof lbl, opcode, fromClient_));
            log::hex(blbl, pkt + headerLen_, keep);

            buf_.erase(buf_.begin(), buf_.begin() + total);
            cryptActive_ = true;
            continue;
        }

        if (!inBody_) {
            if ((int)buf_.size() < headerLen_) return;

            uint8_t header[6];
            memcpy(header, buf_.data(), headerLen_);
            recv_.decrypt(header, headerLen_);
            int size = (header[0] << 8) | header[1];
            int opcode = header[2] | (header[3] << 8);
            int mapped = remap_(opcode);

            buf_.erase(buf_.begin(), buf_.begin() + headerLen_);
            bodyRemaining_ = size - bodyAdjust_;
            if (bodyRemaining_ < 0) bodyRemaining_ = 0;
            inBody_ = true;
            logOpcode_ = opcode;
            mappedOpcode_ = mapped;
            bodyBuf_.clear();

            xformCharEnum_   = (!fromClient_ && opcode == op::mangos::kSMSG_CHAR_ENUM && mapped >= 0);
            xformCharCreate_ = (fromClient_ && mapped == op::mangos::kCMSG_CHAR_CREATE);

            char lbl[64], mlbl[64];
            opLabel(lbl, sizeof lbl, opcode, fromClient_);
            if (mapped < 0) {
                log::line("%s op=%s size=%d -> drop (unmapped client opcode)", tag_, lbl, size);
                forwardBody_ = false;
            } else if (xformCharEnum_ || xformCharCreate_) {
                log::line("%s op=%s size=%d -> %s (%s)", tag_, lbl, size,
                          opLabel(mlbl, sizeof mlbl, mapped, false),
                          xformCharEnum_ ? "reshape" : "trim");
                forwardBody_ = false;          // header follows the rebuilt body, once its size is known
                xformBody_.clear();
            } else {
                if (mapped != opcode) log::line("%s op=%s size=%d -> %s", tag_, lbl, size,
                                                opLabel(mlbl, sizeof mlbl, mapped, false));
                else                  log::line("%s op=%s size=%d", tag_, lbl, size);
                header[2] = (uint8_t)(mapped & 0xff);
                header[3] = (uint8_t)((mapped >> 8) & 0xff);
                send_.encrypt(header, headerLen_);
                net::sendAll(out_, header, headerLen_);
                forwardBody_ = true;
            }
        }

        int take = (int)buf_.size();
        if (take > bodyRemaining_) take = bodyRemaining_;
        if (xformCharEnum_ || xformCharCreate_) {
            if (take > 0) xformBody_.insert(xformBody_.end(), buf_.begin(), buf_.begin() + take);
        } else {
            if (forwardBody_ && take > 0) net::sendAll(out_, buf_.data(), take);

            // Keep a capped copy of the body for the diagnostic hex dump.
            int keep = take;
            if ((int)bodyBuf_.size() + keep > kBodyLogCap)
                keep = kBodyLogCap - (int)bodyBuf_.size();
            if (keep > 0) bodyBuf_.insert(bodyBuf_.end(), buf_.begin(), buf_.begin() + keep);
        }

        buf_.erase(buf_.begin(), buf_.begin() + take);
        bodyRemaining_ -= take;
        if (bodyRemaining_ > 0) return;

        if (xformCharEnum_) {
            emitCharEnum();
        } else if (xformCharCreate_) {
            emitCharCreate();
        } else {
            char lbl[64], label[96];
            snprintf(label, sizeof label, "%s body %s", tag_, opLabel(lbl, sizeof lbl, logOpcode_, fromClient_));
            log::hex(label, bodyBuf_.data(), (int)bodyBuf_.size());
        }

        inBody_ = false;
    }
}

// Reshape the fully buffered vanilla char list into the client's record layout, then send it under a header
// carrying the new size and the renumbered char-enum opcode. Only the header is header-crypted; the body is
// plaintext on the wire, so it is written straight after.
void Pipe::emitCharEnum() {
    Bytes out = reshapeCharEnum(xformBody_.data(), (int)xformBody_.size());
    int newSize = (int)out.size() + bodyAdjust_;

    uint8_t header[6];
    header[0] = (uint8_t)((newSize >> 8) & 0xff);
    header[1] = (uint8_t)(newSize & 0xff);
    header[2] = (uint8_t)(mappedOpcode_ & 0xff);
    header[3] = (uint8_t)((mappedOpcode_ >> 8) & 0xff);
    send_.encrypt(header, headerLen_);
    net::sendAll(out_, header, headerLen_);
    net::sendAll(out_, out.data(), (int)out.size());

    char lbl[96];
    snprintf(lbl, sizeof lbl, "%s SMSG_CHAR_ENUM reshaped %d -> %d body bytes",
             tag_, (int)xformBody_.size(), (int)out.size());
    log::hex(lbl, out.data(), (int)out.size() < kBodyLogCap ? (int)out.size() : kBodyLogCap);
    xformCharEnum_ = false;
}

// Trim the fully buffered CMSG_CHAR_CREATE body to its exact vanilla length and forward it under a header
// carrying the new size and the renumbered opcode. The client appends a trailing byte the vanilla server
// rejects; dropping it lets the create parse cleanly so the server's success reply reaches the client. The
// client->server header is six bytes (a four-byte opcode), so the upper opcode bytes are zeroed.
void Pipe::emitCharCreate() {
    Bytes out = trimCharCreate(xformBody_.data(), (int)xformBody_.size());
    int newSize = (int)out.size() + bodyAdjust_;

    uint8_t header[6] = {0};
    header[0] = (uint8_t)((newSize >> 8) & 0xff);
    header[1] = (uint8_t)(newSize & 0xff);
    header[2] = (uint8_t)(mappedOpcode_ & 0xff);
    header[3] = (uint8_t)((mappedOpcode_ >> 8) & 0xff);
    send_.encrypt(header, headerLen_);
    net::sendAll(out_, header, headerLen_);
    net::sendAll(out_, out.data(), (int)out.size());

    char lbl[96];
    snprintf(lbl, sizeof lbl, "%s CMSG_CHAR_CREATE trimmed %d -> %d body bytes",
             tag_, (int)xformBody_.size(), (int)out.size());
    log::hex(lbl, out.data(), (int)out.size() < kBodyLogCap ? (int)out.size() : kBodyLogCap);
    xformCharCreate_ = false;
}

} // namespace uoa::world
