#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <utility>

namespace uoa {

using Bytes = std::vector<uint8_t>;

// Sequential little-endian writer. Building a packet reads top to bottom.
class ByteWriter {
public:
    void u8(uint8_t v)   { out_.push_back(v); }
    void u16(uint16_t v) { u8(uint8_t(v)); u8(uint8_t(v >> 8)); }
    void u32(uint32_t v) { u16(uint16_t(v)); u16(uint16_t(v >> 16)); }

    void bytes(const uint8_t* p, size_t n) { out_.insert(out_.end(), p, p + n); }
    void bytes(const Bytes& b)             { bytes(b.data(), b.size()); }
    void text(const char* s)               { bytes(reinterpret_cast<const uint8_t*>(s), strlen(s)); }
    void cstr(const std::string& s)        { bytes(reinterpret_cast<const uint8_t*>(s.data()), s.size()); u8(0); }
    void zeros(size_t n)                    { out_.insert(out_.end(), n, uint8_t(0)); }

    size_t        size() const { return out_.size(); }
    const Bytes&  data() const { return out_; }
    Bytes         take()       { return std::move(out_); }

private:
    Bytes out_;
};

// Sequential reader over a fixed buffer. Reads past the end yield zero / empty.
class ByteReader {
public:
    ByteReader(const uint8_t* data, size_t len) : p_(data), end_(data + len) {}

    uint8_t  u8()  { return has(1) ? *p_++ : uint8_t(0); }
    uint16_t u16() { uint16_t lo = u8(); return uint16_t(lo | (u8() << 8)); }
    uint32_t u32() { uint32_t lo = u16(); return lo | (uint32_t(u16()) << 16); }

    void  skip(size_t n)      { p_ += clamp(n); }
    Bytes take(size_t n)      { size_t k = clamp(n); Bytes b(p_, p_ + k); p_ += k; return b; }

    std::string cstr() {
        std::string s;
        while (p_ < end_ && *p_) s += char(*p_++);
        if (p_ < end_) ++p_;   // consume terminator
        return s;
    }

    size_t remaining() const { return size_t(end_ - p_); }

private:
    bool   has(size_t n) const  { return remaining() >= n; }
    size_t clamp(size_t n) const { return n < remaining() ? n : remaining(); }

    const uint8_t* p_;
    const uint8_t* end_;
};

} // namespace uoa
