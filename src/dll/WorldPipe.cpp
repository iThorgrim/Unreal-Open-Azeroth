#include "WorldPipe.h"
#include "Net.h"
#include "Log.h"
#include "Settings.h"

#include <cstring>
#include <cstdio>

namespace uoa::world {

// Cap the diagnostic body dump so a large packet (world state, char list) stays readable in the log.
static constexpr int kBodyLogCap = 128;

Pipe::Pipe(SOCKET out, int headerLen, Remap remap, const char* tag,
           WantRewrite wants, ApplyRewrite apply)
    : out_(out), headerLen_(headerLen), bodyAdjust_(headerLen - 2),
      remap_(remap), tag_(tag), wants_(wants), apply_(apply) {}

void Pipe::feed(const uint8_t* data, int len) {
    buf_.insert(buf_.end(), data, data + len);
    parse();
}

// Emit the buffered body as a re-encrypted packet under `opcode`, with a size derived from it.
void Pipe::emitPacket(int opcode) {
    int size = bodyAdjust_ + (int)bodyBuf_.size();   // size counts the opcode plus the body
    uint8_t header[6];
    header[0] = (uint8_t)((size >> 8) & 0xff);        // size is big-endian
    header[1] = (uint8_t)(size & 0xff);
    header[2] = (uint8_t)(opcode & 0xff);             // opcode is little-endian
    header[3] = (uint8_t)((opcode >> 8) & 0xff);
    send_.encrypt(header, headerLen_);

    net::sendAll(out_, header, headerLen_);
    if (!bodyBuf_.empty()) net::sendAll(out_, bodyBuf_.data(), (int)bodyBuf_.size());
}

// Transform the buffered body, then emit it. Normally one packet under the remapped opcode; in
// sweep mode, one packet per opcode across the configured band so a whole range is probed at once.
void Pipe::flushRewritten(int opcode) {
    log::hex("[world] rewrite in ", bodyBuf_.data(), (int)bodyBuf_.size());
    apply_(opcode, bodyBuf_);
    log::hex("[world] rewrite out", bodyBuf_.data(), (int)bodyBuf_.size());

    const Settings& s = settings();
    if (s.sweepHi > s.sweepLo) {
        // Pad the body with zeros so handlers that read fields see valid nulls (count 0, empty
        // strings, null ids) instead of under-reading a short body and crashing. For a small result
        // opcode (e.g. char-create 0x3A) keep the real body instead, so the client gets a usable
        // result code (sweep_zero = 0).
        if (s.sweepZero) bodyBuf_.assign(64, 0);
        else if ((int)bodyBuf_.size() < 64) bodyBuf_.resize(64, 0);   // keep the real result, pad for safety
        log::line("[world] sweep target 0x%03X across 0x%03X..0x%03X", s.sweepTarget, s.sweepLo, s.sweepHi);
        for (int op = s.sweepLo; op <= s.sweepHi; ++op) {
            if (op == 0x271) continue;                  // known world-load handler
            if (op == s.charEnumOpcode) continue;       // char-list opcode: a result body would corrupt the list
            emitPacket(op);
        }
    } else {
        emitPacket(opcode);
    }
}

void Pipe::parse() {
    for (;;) {
        if (!inBody_) {
            if ((int)buf_.size() < headerLen_) return;

            uint8_t header[6];
            memcpy(header, buf_.data(), headerLen_);

            if (!cryptActive_) {
                // First packet (auth handshake): plaintext, forwarded unchanged.
                int size = (header[0] << 8) | header[1];
                int opcode = header[2] | (header[3] << 8);
                log::line("%s op=0x%04X size=%d (plain)", tag_, opcode, size);
                net::sendAll(out_, buf_.data(), headerLen_);
                buf_.erase(buf_.begin(), buf_.begin() + headerLen_);
                bodyRemaining_ = size - bodyAdjust_;
                if (bodyRemaining_ < 0) bodyRemaining_ = 0;
                forwardBody_ = true;
                buffering_ = false;
                inBody_ = true;
                logOpcode_ = opcode;
                bodyBuf_.clear();
            } else {
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

                if (mapped < 0) {
                    log::line("%s op=0x%04X size=%d -> drop", tag_, opcode, size);
                    forwardBody_ = false;
                    buffering_ = false;
                } else if (wants_ && wants_(opcode)) {
                    // Buffer the whole body, then rewrite and emit it under the remapped opcode.
                    log::line("%s op=0x%04X size=%d -> rewrite 0x%04X", tag_, opcode, size, mapped);
                    forwardBody_ = false;
                    buffering_ = true;
                    rewriteOpcode_ = mapped;
                } else {
                    if (mapped != opcode) log::line("%s op=0x%04X size=%d -> 0x%04X", tag_, opcode, size, mapped);
                    else                  log::line("%s op=0x%04X size=%d", tag_, opcode, size);
                    header[2] = (uint8_t)(mapped & 0xff);
                    header[3] = (uint8_t)((mapped >> 8) & 0xff);
                    send_.encrypt(header, headerLen_);
                    net::sendAll(out_, header, headerLen_);
                    forwardBody_ = true;
                    buffering_ = false;
                }
            }
        }

        int take = (int)buf_.size();
        if (take > bodyRemaining_) take = bodyRemaining_;
        if (forwardBody_ && take > 0) net::sendAll(out_, buf_.data(), take);

        // Collect body bytes: the full body when buffering for a rewrite, otherwise a capped copy
        // for the diagnostic hex dump.
        int keep = take;
        if (!buffering_ && (int)bodyBuf_.size() + keep > kBodyLogCap)
            keep = kBodyLogCap - (int)bodyBuf_.size();
        if (keep > 0) bodyBuf_.insert(bodyBuf_.end(), buf_.begin(), buf_.begin() + keep);

        buf_.erase(buf_.begin(), buf_.begin() + take);
        bodyRemaining_ -= take;
        if (bodyRemaining_ > 0) return;

        if (buffering_) {
            flushRewritten(rewriteOpcode_);
        } else {
            char label[48];
            snprintf(label, sizeof label, "%s body 0x%04X", tag_, logOpcode_);
            log::hex(label, bodyBuf_.data(), (int)bodyBuf_.size());
        }

        inBody_ = false;
        buffering_ = false;
        cryptActive_ = true;
    }
}

} // namespace uoa::world
