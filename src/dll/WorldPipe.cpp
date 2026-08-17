#include "WorldPipe.h"
#include "OpcodeNames.h"
#include "OpCodes.h"
#include "ByteBuffer.h"
#include "Sha1.h"
#include "AuthProxy.h"
#include "WorldKey.h"
#include "Net.h"
#include "Log.h"

#include <cstring>
#include <cstdio>
#include <string>

namespace uoa::world {

// Cap the diagnostic body dump so a large packet (world state, char list) stays readable in the log.
static constexpr int kBodyLogCap = 128;

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
            bodyBuf_.clear();

            char lbl[64], mlbl[64];
            opLabel(lbl, sizeof lbl, opcode, fromClient_);
            if (mapped < 0) {
                log::line("%s op=%s size=%d -> drop (unmapped client opcode)", tag_, lbl, size);
                forwardBody_ = false;
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
        if (forwardBody_ && take > 0) net::sendAll(out_, buf_.data(), take);

        // Keep a capped copy of the body for the diagnostic hex dump.
        int keep = take;
        if ((int)bodyBuf_.size() + keep > kBodyLogCap)
            keep = kBodyLogCap - (int)bodyBuf_.size();
        if (keep > 0) bodyBuf_.insert(bodyBuf_.end(), buf_.begin(), buf_.begin() + keep);

        buf_.erase(buf_.begin(), buf_.begin() + take);
        bodyRemaining_ -= take;
        if (bodyRemaining_ > 0) return;

        char lbl[64], label[96];
        snprintf(label, sizeof label, "%s body %s", tag_, opLabel(lbl, sizeof lbl, logOpcode_, fromClient_));
        log::hex(label, bodyBuf_.data(), (int)bodyBuf_.size());

        inBody_ = false;
    }
}

} // namespace uoa::world
