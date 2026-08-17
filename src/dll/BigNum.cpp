#include "BigNum.h"
#include <cstring>

namespace uoa {

void BigNum::clear() { memset(w, 0, sizeof w); }

bool BigNum::isZero() const {
    for (int i = 0; i < W; ++i) if (w[i]) return false;
    return true;
}

void BigNum::setU32(uint32_t v) { clear(); w[0] = v; }

void BigNum::setBytesBE(const uint8_t* p, int len) {
    clear();
    for (int k = 0; k < len; ++k) {
        int bi = len - 1 - k;                       // byte index from LSB
        if ((bi >> 2) < W) w[bi >> 2] |= (uint32_t)p[k] << (8 * (bi & 3));
    }
}

void BigNum::setBytesLE(const uint8_t* p, int len) {
    clear();
    for (int k = 0; k < len; ++k)
        if ((k >> 2) < W) w[k >> 2] |= (uint32_t)p[k] << (8 * (k & 3));
}

void BigNum::getBytesBE(uint8_t* out, int len) const {
    for (int k = 0; k < len; ++k) {
        int bi = len - 1 - k;
        out[k] = (bi >> 2) < W ? (uint8_t)(w[bi >> 2] >> (8 * (bi & 3))) : 0;
    }
}

void BigNum::getBytesLE(uint8_t* out, int len) const {
    for (int k = 0; k < len; ++k)
        out[k] = (k >> 2) < W ? (uint8_t)(w[k >> 2] >> (8 * (k & 3))) : 0;
}

int BigNum::bitLength() const {
    for (int i = W - 1; i >= 0; --i) {
        if (w[i]) {
            uint32_t x = w[i]; int b = 0;
            while (x) { x >>= 1; ++b; }
            return i * 32 + b;
        }
    }
    return 0;
}

bool BigNum::testBit(int i) const {
    if (i < 0 || i >= W * 32) return false;
    return (w[i >> 5] >> (i & 31)) & 1u;
}

int BigNum::cmp(const BigNum& o) const {
    for (int i = W - 1; i >= 0; --i)
        if (w[i] != o.w[i]) return w[i] < o.w[i] ? -1 : 1;
    return 0;
}

void BigNum::shl1() {
    uint32_t carry = 0;
    for (int i = 0; i < W; ++i) {
        uint32_t next = w[i] >> 31;
        w[i] = (w[i] << 1) | carry;
        carry = next;
    }
}

void BigNum::addTo(const BigNum& o) {
    uint64_t carry = 0;
    for (int i = 0; i < W; ++i) {
        uint64_t cur = (uint64_t)w[i] + o.w[i] + carry;
        w[i] = (uint32_t)cur;
        carry = cur >> 32;
    }
}

void BigNum::subFrom(const BigNum& o) {
    int64_t borrow = 0;
    for (int i = 0; i < W; ++i) {
        int64_t cur = (int64_t)w[i] - (int64_t)o.w[i] - borrow;
        if (cur < 0) { cur += (int64_t)1 << 32; borrow = 1; } else borrow = 0;
        w[i] = (uint32_t)cur;
    }
}

BigNum BigNum::add(const BigNum& a, const BigNum& b) {
    BigNum r; uint64_t carry = 0;
    for (int i = 0; i < W; ++i) {
        uint64_t cur = (uint64_t)a.w[i] + b.w[i] + carry;
        r.w[i] = (uint32_t)cur;
        carry = cur >> 32;
    }
    return r;
}

BigNum BigNum::mul(const BigNum& a, const BigNum& b) {
    BigNum r; r.clear();
    for (int i = 0; i < W; ++i) {
        if (!a.w[i]) continue;
        uint64_t carry = 0;
        for (int j = 0; i + j < W; ++j) {
            uint64_t cur = (uint64_t)r.w[i + j] + (uint64_t)a.w[i] * b.w[j] + carry;
            r.w[i + j] = (uint32_t)cur;
            carry = cur >> 32;
        }
    }
    return r;
}

BigNum BigNum::modAdd(const BigNum& a, const BigNum& b, const BigNum& n) {
    BigNum r = add(a, b);
    if (r.cmp(n) >= 0) r.subFrom(n);
    return r;
}

BigNum BigNum::modSub(const BigNum& a, const BigNum& b, const BigNum& n) {
    BigNum r = a;
    if (a.cmp(b) >= 0) r.subFrom(b);
    else { r.addTo(n); r.subFrom(b); }
    return r;
}

BigNum BigNum::modMul(const BigNum& a, const BigNum& b, const BigNum& n) {
    BigNum res; res.clear();
    int bits = b.bitLength();
    for (int i = bits - 1; i >= 0; --i) {
        res.shl1();
        if (res.cmp(n) >= 0) res.subFrom(n);
        if (b.testBit(i)) {
            res.addTo(a);
            if (res.cmp(n) >= 0) res.subFrom(n);
        }
    }
    return res;
}

BigNum BigNum::modExp(const BigNum& base, const BigNum& exp, const BigNum& n) {
    BigNum res; res.setU32(1);
    BigNum b = base;
    while (b.cmp(n) >= 0) b.subFrom(n);       // no-op when base < n (our case)
    int bits = exp.bitLength();
    for (int i = bits - 1; i >= 0; --i) {
        res = modMul(res, res, n);
        if (exp.testBit(i)) res = modMul(res, b, n);
    }
    return res;
}

} // namespace uoa
