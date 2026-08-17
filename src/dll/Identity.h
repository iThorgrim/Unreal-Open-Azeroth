#pragma once
#include <cstdint>
#include <string>

// Captures the SRP identity hash from the client's auth object at runtime, so the proxy can drive
// SRP itself without ever seeing the password in a file. The client stores the (already uppercased)
// username and password as wide strings in the auth object; we read them, compute
// I = SHA1(UPPER(user):UPPER(pass)) in-process, and keep only the 20-byte digest.
namespace uoa::identity {

void               captureFrom(void* authObject);   // read user/pass, compute and store I
bool               ready();
const uint8_t*     hash();                            // 20-byte identity digest, or nullptr
const std::string& user();                            // captured username (safe to log)

} // namespace uoa::identity
