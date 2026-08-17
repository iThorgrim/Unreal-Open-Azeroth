#include "Srp.h"
#include "BigNum.h"
#include "Sha1.h"
#include "Log.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace uoa::srp {
namespace {

// Classic WoW / cmangos modulus (big-endian), g=7.
const uint8_t kNClassic[32] = {
    0x89,0x4B,0x64,0x5E,0x89,0xE1,0x53,0x5B,0xBD,0xAD,0x5B,0x8B,0x29,0x06,0x50,0x53,
    0x08,0x01,0xB1,0x8E,0xBF,0xBF,0x5E,0x8F,0xAB,0x3C,0x82,0x87,0x2A,0x3E,0x9B,0xB7,
};
// Emberveil AZRT modulus (big-endian), g=2.
const uint8_t kNCustom[32] = {
    0xD4,0xC7,0xFE,0x87,0xA4,0x4D,0x2E,0x10,0x8E,0xF8,0x4A,0xC0,0xA8,0x3D,0x89,0x7E,
    0x2A,0x4F,0xD6,0xA1,0xB9,0xF5,0x8F,0xE8,0xEC,0x31,0x51,0xBD,0x47,0xE8,0xD5,0xEF,
};

void toHex(const uint8_t* p, int n, char* out) {
    for (int i = 0; i < n; ++i) _snprintf(out + i * 2, 3, "%02x", p[i]);
}

void fillRandom(uint8_t* p, int n) {
    static uint64_t st = 0;
    if (!st) {
        LARGE_INTEGER li; QueryPerformanceCounter(&li);
        st = (uint64_t)li.QuadPart ^ 0x9E3779B97F4A7C15ull ^ GetTickCount64();
    }
    for (int i = 0; i < n; ++i) {
        st ^= st << 13; st ^= st >> 7; st ^= st << 17;
        p[i] = (uint8_t)(st >> 24);
    }
}

// Feed a BigNum into SHA-1 as minimal little-endian bytes, matching cmangos BigNumber::AsByteArray().
void updBN(Sha1& sha, const BigNum& n) {
    int len = (n.bitLength() + 7) / 8;
    if (len <= 0) return;
    uint8_t buf[96];
    if (len > (int)sizeof buf) len = sizeof buf;
    n.getBytesLE(buf, len);
    sha.update(buf, len);
}

// u = SHA1(A_minLE, B_minLE) as a little-endian integer.
BigNum calcU(const BigNum& A, const BigNum& B) {
    Sha1 sha; updBN(sha, A); updBN(sha, B);
    uint8_t d[20]; sha.finish(d);
    BigNum u; u.setBytesLE(d, 20); return u;
}

// K = interleave(S): even bytes -> SHA1 -> K[0,2,4..], odd bytes -> SHA1 -> K[1,3,5..].
void interleaveK(const BigNum& S, uint8_t outK[40]) {
    uint8_t s32[32]; S.getBytesLE(s32, 32);
    uint8_t half[16], h[20];
    for (int i = 0; i < 16; ++i) half[i] = s32[i * 2];
    { Sha1 sha; sha.update(half, 16); sha.finish(h); for (int i = 0; i < 20; ++i) outK[i * 2] = h[i]; }
    for (int i = 0; i < 16; ++i) half[i] = s32[i * 2 + 1];
    { Sha1 sha; sha.update(half, 16); sha.finish(h); for (int i = 0; i < 20; ++i) outK[i * 2 + 1] = h[i]; }
}

// x = SHA1(salt_minLE, I) as a little-endian integer.
BigNum calcX(const uint8_t saltWire[32], const uint8_t identity[20]) {
    BigNum saltBN; saltBN.setBytesLE(saltWire, 32);
    Sha1 sha; updBN(sha, saltBN); sha.update(identity, 20);
    uint8_t d[20]; sha.finish(d);
    BigNum x; x.setBytesLE(d, 20); return x;
}

} // namespace

void azrtChallenge(const uint8_t identity[20], AzrtServer& s) {
    BigNum N; N.setBytesBE(kNCustom, 32);
    BigNum g; g.setU32(2);

    fillRandom(s.saltWire, 32);
    s.saltWire[31] |= 0x80;                    // keep the salt a full 32-byte value

    uint8_t bRand[32]; fillRandom(bRand, 32);
    BigNum b; b.setBytesBE(bRand, 32);
    while (b.cmp(N) >= 0) b.subFrom(N);

    BigNum x = calcX(s.saltWire, identity);
    BigNum v = BigNum::modExp(g, x, N);
    BigNum gb = BigNum::modExp(g, b, N);
    BigNum three; three.setU32(3);
    BigNum B = BigNum::modAdd(BigNum::modMul(v, three, N), gb, N);

    b.getBytesBE(s.bBytes, 32);
    v.getBytesBE(s.vBytes, 32);
    B.getBytesLE(s.Bwire, 32);
    N.getBytesLE(s.Nwire, 32);
}

void azrtFinish(const AzrtServer& s, const uint8_t Awire[32], const uint8_t M1[20],
                uint8_t outM2[20], uint8_t outK[40]) {
    BigNum N; N.setBytesBE(kNCustom, 32);
    BigNum A; A.setBytesLE(Awire, 32);
    BigNum B; B.setBytesLE(s.Bwire, 32);
    BigNum v; v.setBytesBE(s.vBytes, 32);
    BigNum b; b.setBytesBE(s.bBytes, 32);

    BigNum u = calcU(A, B);
    BigNum S = BigNum::modExp(BigNum::modMul(A, BigNum::modExp(v, u, N), N), b, N);

    uint8_t K[40]; interleaveK(S, K);
    if (outK) memcpy(outK, K, 40);

    BigNum M1bn; M1bn.setBytesLE(M1, 20);
    BigNum Kbn;  Kbn.setBytesLE(K, 40);
    Sha1 sha; updBN(sha, A); updBN(sha, M1bn); updBN(sha, Kbn);
    sha.finish(outM2);
}

bool classicClientProof(const uint8_t* c, int len, const char* upperUser,
                        const uint8_t I[20], uint8_t outAwire[32], uint8_t outM1[20], uint8_t outK[40]) {
    if (len < 119) return false;
    // Challenge layout: cmd(0) err(1) unk2(2) B[3..34] gLen(35) g(36) NLen(37) N[38..69] salt[70..101].
    const uint8_t* Bwire    = c + 3;
    uint8_t        gVal     = c[36];
    const uint8_t* Nwire    = c + 38;
    const uint8_t* saltWire = c + 70;

    BigNum N; N.setBytesLE(Nwire, 32);
    BigNum g; g.setU32(gVal);
    BigNum B; B.setBytesLE(Bwire, 32);

    // a random, A = g^a mod N.
    uint8_t aRand[32]; fillRandom(aRand, 32);
    BigNum a; a.setBytesBE(aRand, 32);
    while (a.cmp(N) >= 0) a.subFrom(N);
    BigNum A = BigNum::modExp(g, a, N);
    A.getBytesLE(outAwire, 32);

    // x = SHA1(salt[32] || I) as a little-endian integer (matches the server's stored verifier).
    uint8_t xd[20];
    { Sha1 s; s.update(saltWire, 32); s.update(I, 20); s.finish(xd); }
    BigNum x; x.setBytesLE(xd, 20);

    BigNum u = calcU(A, B);
    // S = (B - 3 * g^x)^(a + u*x) mod N.
    BigNum gx    = BigNum::modExp(g, x, N);
    BigNum three; three.setU32(3);
    BigNum base  = BigNum::modSub(B, BigNum::modMul(three, gx, N), N);
    BigNum e     = BigNum::add(a, BigNum::mul(u, x));
    BigNum S     = BigNum::modExp(base, e, N);
    interleaveK(S, outK);

    // M1 = SHA1( (SHA1(N) xor SHA1(g)) || SHA1(user) || salt[32] || A_minLE || B_minLE || K ).
    uint8_t hN[20], hg[20];
    { Sha1 s; updBN(s, N); s.finish(hN); }
    { Sha1 s; updBN(s, g); s.finish(hg); }
    uint8_t t[20]; for (int i = 0; i < 20; ++i) t[i] = hN[i] ^ hg[i];
    BigNum tBN; tBN.setBytesLE(t, 20);

    uint8_t hU[20];
    { Sha1 s; s.update(reinterpret_cast<const uint8_t*>(upperUser), (int)strlen(upperUser)); s.finish(hU); }

    BigNum Abn; Abn.setBytesLE(outAwire, 32);
    Sha1 m1; updBN(m1, tBN); m1.update(hU, 20); m1.update(saltWire, 32);
    updBN(m1, Abn); updBN(m1, B); m1.update(outK, 40);
    m1.finish(outM1);
    return true;
}

} // namespace uoa::srp
