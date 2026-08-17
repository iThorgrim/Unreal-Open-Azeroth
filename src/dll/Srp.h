#pragma once
#include <cstdint>

// SRP for the auth bridge. The proxy plays the AZRT server to the client: it owns the ephemeral,
// derives the verifier from the captured identity, and produces the M2 the client checks. Custom
// Emberveil parameters (256-bit prime, g=2, k=3, minimal-LE hashing).
namespace uoa::srp {

// Per-connection challenge state produced by azrtChallenge; its salt/B/N are what a1 sends. The verifier is
// a placeholder, so bBytes/vBytes are unused after the challenge is built.
struct AzrtServer {
    uint8_t saltWire[32];   // salt sent in a1
    uint8_t Bwire[32];      // server public ephemeral B, little-endian, for a1
    uint8_t Nwire[32];      // modulus N, little-endian, for a1
    // internal
    uint8_t bBytes[32];
    uint8_t vBytes[32];
};


// Fill s (salt/B/N) from the 20-byte identity hash I. Sends g=2. The verifier is a placeholder: the client
// derives its own session key from B, and we read that key back rather than reproduce it.
void azrtChallenge(const uint8_t identity[20], AzrtServer& s);

// Compute the a3 proof M2 = SHA1(A, M1, K) the client's proof-verify expects, from the client's A and M1
// (from a2) and the 40-byte session key K the client itself derived (captured from its SRP state by the a1
// detour). clientK is 40 little-endian bytes.
void azrtFinish(const uint8_t Awire[32], const uint8_t M1[20], const uint8_t clientK[40], uint8_t outM2[20]);

// Classic cmangos SRP6 CLIENT side: from the 119-byte realmd logon challenge (which carries B, g, N,
// salt) plus the uppercased account name and captured identity I, produce the wire-order A[32] and
// proof M1[20] to send in CMD_AUTH_LOGON_PROOF, and the 40-byte session key K. Uses N/g exactly as
// the server sent them. Returns false if the challenge is too short.
bool classicClientProof(const uint8_t* challenge, int len, const char* upperUser,
                        const uint8_t identity[20], uint8_t outAwire[32], uint8_t outM1[20],
                        uint8_t outK[40]);

} // namespace uoa::srp
