#include "Identity.h"
#include "Sha1.h"
#include "Log.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstring>

namespace uoa::identity {
namespace {

// Offsets into the client auth object (confirmed by dumping the object at the a1 handler): each
// field holds a pointer to a null-terminated wide string, already uppercased by the client.
constexpr int kUserFieldOff = 0x68;
constexpr int kPassFieldOff = 0x78;

uint8_t     g_hash[20] = {};          // SHA1(user:pass) - matches the cmangos account verifier (hat-2)
bool        g_ready    = false;
std::string g_user;

// Read the wide string whose pointer sits at object+fieldOff into an ASCII buffer. SEH-guarded and
// free of C++ objects so the __try is valid.
bool readWideField(const void* obj, int fieldOff, char* out, int cap) {
    __try {
        auto ws = *reinterpret_cast<const wchar_t* const*>(
            reinterpret_cast<const uint8_t*>(obj) + fieldOff);
        if (!ws) return false;
        int i = 0;
        for (; i < cap - 1 && ws[i]; ++i)
            out[i] = static_cast<char>(ws[i] & 0xFF);
        out[i] = '\0';
        return i > 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

} // namespace

void captureFrom(void* obj) {
    if (!obj) return;

    char user[64], pass[64];
    if (!readWideField(obj, kUserFieldOff, user, sizeof user)) return;
    if (!readWideField(obj, kPassFieldOff, pass, sizeof pass)) return;

    // I = SHA1(user ":" pass), on the exact stored (uppercased) bytes the client itself hashes. cmangos
    // stores the account verifier against this, which hat-2 uses to validate the account.
    Sha1 sha;
    sha.update(reinterpret_cast<const uint8_t*>(user), strlen(user));
    sha.update(reinterpret_cast<const uint8_t*>(":"), 1);
    sha.update(reinterpret_cast<const uint8_t*>(pass), strlen(pass));
    uint8_t digest[20];
    sha.finish(digest);

    // Wipe the plaintext copies as soon as we are done with them.
    SecureZeroMemory(pass, sizeof pass);

    bool changed = !g_ready || memcmp(g_hash, digest, 20) != 0;
    memcpy(g_hash, digest, 20);
    g_user = user;
    g_ready = true;

    if (changed) {   // log the resulting digest + username only - never the password
        char hex[41];
        for (int i = 0; i < 20; ++i)
            _snprintf(hex + i * 2, 3, "%02x", digest[i]);
        log::line("[id] identity captured user=%s I=%s", user, hex);
    }
}

bool               ready() { return g_ready; }
const uint8_t*     hash()  { return g_ready ? g_hash : nullptr; }
const std::string& user()  { return g_user; }

} // namespace uoa::identity
