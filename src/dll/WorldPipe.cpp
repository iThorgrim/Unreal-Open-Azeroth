#include "WorldPipe.h"
#include "Net.h"
#include "Log.h"

#include <cstring>

namespace uoa::world {

Pipe::Pipe(SOCKET out, int headerLen, Remap remap, const char* tag)
    : out_(out), headerLen_(headerLen), bodyAdjust_(headerLen - 2), remap_(remap), tag_(tag) {}

void Pipe::feed(const uint8_t* data, int len) {
    buf_.insert(buf_.end(), data, data + len);
    parse();
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
                inBody_ = true;
            } else {
                recv_.decrypt(header, headerLen_);
                int size = (header[0] << 8) | header[1];
                int opcode = header[2] | (header[3] << 8);
                int mapped = remap_(opcode);

                buf_.erase(buf_.begin(), buf_.begin() + headerLen_);
                bodyRemaining_ = size - bodyAdjust_;
                if (bodyRemaining_ < 0) bodyRemaining_ = 0;
                inBody_ = true;

                if (mapped < 0) {
                    log::line("%s op=0x%04X size=%d -> drop", tag_, opcode, size);
                    forwardBody_ = false;
                } else {
                    if (mapped != opcode) log::line("%s op=0x%04X size=%d -> 0x%04X", tag_, opcode, size, mapped);
                    else                  log::line("%s op=0x%04X size=%d", tag_, opcode, size);
                    header[2] = (uint8_t)(mapped & 0xff);
                    header[3] = (uint8_t)((mapped >> 8) & 0xff);
                    send_.encrypt(header, headerLen_);
                    net::sendAll(out_, header, headerLen_);
                    forwardBody_ = true;
                }
            }
        }

        int take = (int)buf_.size();
        if (take > bodyRemaining_) take = bodyRemaining_;
        if (forwardBody_ && take > 0) net::sendAll(out_, buf_.data(), take);
        buf_.erase(buf_.begin(), buf_.begin() + take);
        bodyRemaining_ -= take;
        if (bodyRemaining_ > 0) return;

        inBody_ = false;
        cryptActive_ = true;
    }
}

} // namespace uoa::world
