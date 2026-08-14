#include "WorldStream.h"
#include "Log.h"

#include <cstring>

namespace uoa::world {

Stream::Stream(Direction dir, const char* tag)
    : dir_(dir), tag_(tag), headerLen_(dir == ClientToServer ? 6 : 4) {}

void Stream::feed(const uint8_t* data, int len) {
    buf_.insert(buf_.end(), data, data + len);
    parse();
}

void Stream::parse() {
    for (;;) {
        if (!inBody_) {
            if ((int)buf_.size() < headerLen_) return;

            uint8_t header[6];
            memcpy(header, buf_.data(), headerLen_);
            if (cryptActive_) cipher_.decrypt(header, headerLen_);

            int size   = (header[0] << 8) | header[1];   // big-endian
            int opcode = header[2] | (header[3] << 8);   // little-endian (low 16 bits)
            int adjust = (dir_ == ClientToServer) ? 4 : 2;
            int body   = size - adjust;
            if (body < 0) body = 0;

            log::line("%s op=0x%04X size=%d", tag_, opcode, size);
            buf_.erase(buf_.begin(), buf_.begin() + headerLen_);
            bodyRemaining_ = body;
            inBody_ = true;
        }

        int take = (int)buf_.size();
        if (take > bodyRemaining_) take = bodyRemaining_;
        buf_.erase(buf_.begin(), buf_.begin() + take);
        bodyRemaining_ -= take;
        if (bodyRemaining_ > 0) return;

        inBody_ = false;
        cryptActive_ = true;
    }
}

} // namespace uoa::world
