#pragma once

// Runtime capture of the AZ-TICKET-v1 KDF at RVA 0x126CA0: dumps the auth-session inputs (K, the
// ticket we sent, username) and the derived output, so the ticket/RC4 derivation can be
// reconstructed offline instead of reversing the string-builder pipeline statically.
namespace uoa::ticketprobe {

void install();

} // namespace uoa::ticketprobe
