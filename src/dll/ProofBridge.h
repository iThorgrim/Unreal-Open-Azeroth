#pragma once
#include <cstdint>

// The a3 proof-verify (a CRC-protected canary) recomputes the expected M2 from its own SRP state and
// compares it to the M2 we sent. Our AZRT M2 differs from the client's custom bignum-hash, so rather
// than reproduce their formula we make the client's freshly computed digest equal the M2 we sent - its
// comparison then passes and its own success path (auth-complete) runs. Only this redundant server-proof
// self-check is aligned; the a1 integrity stays legitimate (validated on our keys).

namespace uoa::proof {

void install();                          // hook the proof-verify's digest finalize
void setSentM2(const uint8_t m2[20]);    // record the M2 we put in a3, so the self-check matches it

}
