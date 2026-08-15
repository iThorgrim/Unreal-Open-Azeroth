#pragma once
#include <cstdint>
#include <vector>
#include "Settings.h"

namespace uoa::world {

// The client speaks the vanilla 1.12 wire format for the char list (u8 count + vanilla records),
// only under a renumbered opcode - so the char list needs no body transform, just the opcode
// relabel in mapServerOpcode. The body-rewrite path now serves discovery only: it is engaged
// solely while a sweep is active, on the opcode being swept.
inline bool wantsBodyRewrite(int serverOpcode) {
    const Settings& s = settings();
    bool sweeping = s.autoSweep || s.sweepHi > s.sweepLo;
    return sweeping && serverOpcode == s.sweepTarget;
}

// Only reached during a sweep, where flushRewritten replaces the body with a zero probe anyway,
// so this just needs to leave a well-formed buffer.
inline void rewriteCharEnum(int /*serverOpcode*/, std::vector<uint8_t>& /*body*/) {}

} // namespace uoa::world
