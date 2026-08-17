#pragma once
#include <cstdint>

// Minimal fixed-width big integer for SRP (256-bit modulus, 512-bit exponents/products). Words are
// little-endian (w[0] is least significant). Zero external dependencies. Not constant-time - fine
// for a one-shot local login bridge, not for a hardened server.
namespace uoa {

struct BigNum {
    static constexpr int W = 20;          // 640 bits: holds <2N temps, 512-bit exponents and products
    uint32_t w[W];

    void clear();
    bool isZero() const;
    void setU32(uint32_t v);
    void setBytesBE(const uint8_t* p, int len);   // p[0] is most significant
    void setBytesLE(const uint8_t* p, int len);   // p[0] is least significant
    void getBytesBE(uint8_t* out, int len) const;
    void getBytesLE(uint8_t* out, int len) const;

    int  bitLength() const;
    bool testBit(int i) const;
    int  cmp(const BigNum& o) const;              // -1 / 0 / 1
    void shl1();
    void addTo(const BigNum& o);                  // this += o (mod 2^640)
    void subFrom(const BigNum& o);                // this -= o (requires this >= o)

    static BigNum add(const BigNum& a, const BigNum& b);                       // full sum
    static BigNum mul(const BigNum& a, const BigNum& b);                       // full product
    static BigNum modAdd(const BigNum& a, const BigNum& b, const BigNum& n);   // a,b < n
    static BigNum modSub(const BigNum& a, const BigNum& b, const BigNum& n);   // a,b < n
    static BigNum modMul(const BigNum& a, const BigNum& b, const BigNum& n);   // a,b < n (double-and-add)
    static BigNum modExp(const BigNum& base, const BigNum& exp, const BigNum& n); // base < n
};

} // namespace uoa
