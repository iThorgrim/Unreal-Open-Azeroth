#include "AuthProxy.h"
#include "ByteBuffer.h"
#include "Sha1.h"
#include "Net.h"
#include "Settings.h"
#include "Config.h"
#include "Identity.h"
#include "Srp.h"
#include "AuthProbe.h"
#include "AzctCanary.h"
#include "OpCodes.h"
#include "Log.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <cstring>

namespace uoa::auth {

std::atomic<bool> g_realmReady{false};
std::atomic<bool> g_sessionReady{false};

namespace {

uint8_t g_sessionKey[40];

} // namespace

const uint8_t* sessionKey()    { return g_sessionReady.load() ? g_sessionKey : nullptr; }
int            sessionKeyLen() { return 40; }

namespace {

// mangos WindowsHash(5875): the realmd version check expects crc_hash = SHA1(A || this).
const uint8_t kWindowsHash5875[20] = {
    0x95, 0xED, 0xB2, 0x7C, 0x78, 0x23, 0xB3, 0x63, 0xCB, 0xDD,
    0xAB, 0x56, 0xA3, 0x92, 0xE7, 0xCB, 0x73, 0xFC, 0xCA, 0x20,
};

} // namespace

// The AZRT client parses its realm list in the post-2.0.3 (TBC-shaped) form, not the classic 1.12 realmd
// form cmangos emits: the realm count is a u16, the realm type is a single byte, and every realm carries a
// lock byte and a realm-flags byte where classic carries one flags byte. Transcode the classic body cmangos
// returns into that shape, otherwise the client reads the name at the wrong offset and its realm-select
// screen mishandles the list. Classic per realm: u32 type, u8 flags, name cstr, address cstr, float
// population, u8 characters, u8 category, u8 id, plus an optional 5-byte build block when flags has
// SPECIFYBUILD (0x04); that block is dropped, as the AZRT client never requests it.
static Bytes azrtRealmBody(const uint8_t* body, int len) {
    ByteReader r(body, len);
    ByteWriter out;
    r.take(4);                            // classic u32 header (unused)
    out.u32(0);                           // AZRT u32 header (unused)
    uint8_t count = r.u8();
    out.u16(count);                       // AZRT realm count is a u16
    for (uint8_t i = 0; i < count; ++i) {
        uint32_t icon = r.u32();
        uint8_t  flags = r.u8();
        out.u8(uint8_t(icon));            // realm type is a single byte in this form
        out.u8(0);                        // lock: a single local realm is never locked
        out.u8(uint8_t(flags & ~0x04));   // realm flags, SPECIFYBUILD cleared so no build block follows
        out.cstr(r.cstr());               // realm name
        out.cstr(r.cstr());               // realm address (host:port)
        out.bytes(r.take(4));             // float population
        out.u8(r.u8());                   // characters
        out.u8(r.u8());                   // realm category
        out.u8(r.u8());                   // realm id
        if (flags & 0x04) r.take(5);      // consume the classic build block, not forwarded
    }
    r.take(2);                            // classic u16 trailer
    out.u16(0x0010);                      // AZRT trailer
    return out.take();
}

// One realm, synthesized locally (fallback when cmangos realmd is unreachable).
static Bytes synthRealmlist() {
    ByteWriter body;
    body.u32(0);                                      // unused header
    body.u16(1);                                      // realm count (u16)
    body.u8(0);                                       // realm type
    body.u8(0);                                       // lock
    body.u8(0);                                       // realm flags
    body.cstr("Unreal Open Azeroth");                 // name
    body.cstr("127.0.0.1:8085");                      // address (read unconditionally by the b1 handler)
    body.u32(0);                                      // population
    body.u8(0);                                       // characters
    body.u8(1);                                       // category
    body.u8(1);                                       // realm id
    body.u16(0x0010);                                 // trailer

    ByteWriter pkt;
    pkt.u8(op::azrt::kRealmList);
    pkt.u16(uint16_t(body.size()));
    pkt.bytes(body.data());
    return pkt.take();
}

// Hat 2: authenticate the proxy against the local cmangos realmd with the captured identity (real
// classic SRP6, not the client's N-mismatched proof), then pull the real realm list. Logs the raw
// cmangos realm-list body (its exact layout is core/build specific - reformat it precisely once seen)
// and returns the 40-byte cmangos session key via outK. Returns false on any failure.
static bool cmangosFetchRealms(uint8_t outK[40], Bytes& outB1) {
    log::line("[hat2] dialing cmangos realmd %s:%u", settings().forwardHost.c_str(), config::kRealmdPort);
    SOCKET rd = net::dial(settings().forwardHost.c_str(), config::kRealmdPort);
    if (rd == INVALID_SOCKET) { log::line("[hat2] realmd unreachable"); return false; }

    DWORD rcvto = 1200;   // keep hat-2 fast: the client disconnects if its b0 goes unanswered too long
    setsockopt(rd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&rcvto), sizeof rcvto);

    std::string account = identity::user();   // already uppercase

    ByteWriter body;
    body.text("WoW");  body.u8(0);
    body.u8(1); body.u8(12); body.u8(1);
    body.u16(config::kBuild);
    body.text("68x"); body.u8(0);
    body.text("niW"); body.u8(0);
    body.text("SUne");
    body.u32(0);
    body.u8(127); body.u8(0); body.u8(0); body.u8(1);
    body.u8(uint8_t(account.size()));
    body.text(account.c_str());
    ByteWriter pkt; pkt.u8(op::realmd::kLogonChallenge); pkt.u8(0x08); pkt.u16(uint16_t(body.size())); pkt.bytes(body.data());
    Bytes chal = pkt.take();
    net::sendAll(rd, chal.data(), int(chal.size()));

    uint8_t c[256];
    int cl = net::recvExact(rd, c, 119);
    if (cl < 119 || c[1] != 0x00) {
        log::hex("[hat2] challenge reply (short/err)", c, cl > 0 ? cl : 0);
        log::line("[hat2] challenge failed (len=%d)", cl);
        closesocket(rd); return false;
    }

    uint8_t A[32], M1[20];
    if (!srp::classicClientProof(c, cl, account.c_str(), identity::hash(), A, M1, outK)) {
        log::line("[hat2] proof calc failed"); closesocket(rd); return false;
    }

    Sha1 crcSha; crcSha.update(A, 32); crcSha.update(kWindowsHash5875, sizeof kWindowsHash5875);
    uint8_t crc[20]; crcSha.finish(crc);

    ByteWriter pw;
    pw.u8(op::realmd::kLogonProof); pw.bytes(Bytes(A, A + 32)); pw.bytes(Bytes(M1, M1 + 20));
    pw.bytes(crc, sizeof crc); pw.u8(0); pw.u8(0);   // crc_hash, numKeys, securityFlags
    Bytes proof = pw.take();
    net::sendAll(rd, proof.data(), int(proof.size()));

    // The whole proof reply arrives in one segment; grab it in a single recv so we never wait on a
    // fixed length that the core may not send (that stall is what timed the client out).
    uint8_t pr[64];
    int prn = recv(rd, reinterpret_cast<char*>(pr), sizeof pr, 0);
    if (prn < 2 || pr[1] != 0x00) {
        log::line("[hat2] cmangos rejected proof (n=%d error=0x%02X)", prn, prn > 1 ? pr[1] : 0xff);
        closesocket(rd); return false;
    }
    log::line("[hat2] *** cmangos auth OK (account=%s) ***", account.c_str());

    uint8_t rlreq[5] = { op::realmd::kRealmList, 0, 0, 0, 0 };   // CMD_REALM_LIST + u32 padding
    net::sendAll(rd, rlreq, 5);
    uint8_t hdr[3];
    if (net::recvExact(rd, hdr, 3) >= 3 && hdr[0] == op::realmd::kRealmList) {
        uint16_t rsize = uint16_t(hdr[1] | (hdr[2] << 8));
        uint8_t rbody[1024];
        if (rsize > sizeof rbody) rsize = sizeof rbody;
        int got = net::recvExact(rd, rbody, rsize);
        log::hex("[hat2] cmangos realmlist body", rbody, got);
        // Transcode cmangos's classic realmd body into the TBC-shaped list the AZRT client parses.
        if (got >= 6) {
            Bytes az = azrtRealmBody(rbody, got);
            ByteWriter p; p.u8(op::azrt::kRealmList); p.u16(uint16_t(az.size())); p.bytes(az);
            outB1 = p.take();
            log::hex("[hat2] -> client b1 (real)", outB1.data(), int(outB1.size()));
        }
    } else {
        log::line("[hat2] no realm list reply");
    }
    closesocket(rd);
    return true;
}

// Hat 1: the DLL plays the AZRT server to the client (custom N/g=2). We cannot reproduce the client's
// session key from the challenge (its verifier derivation is opaque), so we do not try: we send a
// placeholder-verifier challenge, let the client derive its own key K from it, and the a1 detour reads K
// back out of the client's SRP state. The a3 proof is then M2 = SHA1(A, M1, K) over that captured K, which
// the client's own proof-verify accepts. hat-2 below runs a real classic SRP against cmangos with the
// captured identity, which is what actually validates the account.
static void azrtServe(SOCKET client) {
    static const uint8_t kPlaceholderId[20] = {
        0x55,0x4e,0x52,0x45,0x41,0x4c,0x4f,0x50,0x45,0x4e,0x41,0x5a,0x45,0x52,0x4f,0x54,0x48,0x2d,0x76,0x31 };
    srp::AzrtServer sv;
    srp::azrtChallenge(kPlaceholderId, sv);

    ByteWriter body;
    body.bytes(Bytes(sv.Bwire,    sv.Bwire    + 32));
    body.bytes(Bytes(sv.Nwire,    sv.Nwire    + 32));
    body.bytes(Bytes(sv.saltWire, sv.saltWire + 32));
    body.u16(2);                                            // g = 2 (uint16 LE)
    for (uint8_t b : azct::kSlot0Key) body.u8(b);   // 32-byte AZCT token = our slot-0 key
    ByteWriter pkt;
    pkt.u8(op::azrt::kChallenge); pkt.u8(0x00);
    pkt.u16(uint16_t(body.size()));                         // 130 = 98 SRP + 32 token
    pkt.bytes(body.data());
    Bytes a1 = pkt.take();
    log::hex("[auth] ->a1(azrt)", a1.data(), int(a1.size()));
    net::sendAll(client, a1.data(), int(a1.size()));

    uint8_t buf[4096];
    int n = recv(client, reinterpret_cast<char*>(buf), sizeof buf, 0);
    // The client socket is blocking, so recv only returns <=0 on a real close: 0 = graceful FIN,
    // -1 = abortive (WSAGetLastError distinguishes a client reset (10054) from a stack abort (10053)).
    if (n <= 0) { log::line("[auth] azrt: no a2 (recv=%d err=%d)", n, WSAGetLastError()); return; }
    log::hex("[auth] <-a2(azrt)", buf, n);
    if (buf[0] != op::azrt::kChallengeReply || n < 55) { log::line("[auth] azrt: bad a2"); return; }

    const uint8_t* A  = buf + 3;    // A[32]
    const uint8_t* M1 = buf + 35;   // M1[20]
    // Validate the account against the real cmangos server BEFORE completing auth. The client has now
    // computed its I (captured by the identity hook while it answered a1), so hat-2 runs a real classic
    // SRP against cmangos - unknown accounts / wrong passwords are rejected there. We forward that as an
    // a3 error, so despite the placeholder AZRT verifier only genuinely valid accounts get in.
    uint8_t cmangosK[40];
    Bytes   realB1;
    bool cmangosOk = cmangosFetchRealms(cmangosK, realB1);
    log::line("[auth] hat2 %s", cmangosOk ? "ok" : "FAILED");
    if (!cmangosOk) {
        Bytes bad = { op::azrt::kProof, 0x04 }; bad.resize(26, 0);   // login-failed status -> the client shows the error
        log::hex("[auth] ->a3 REJECT (cmangos declined the account)", bad.data(), int(bad.size()));
        net::sendAll(client, bad.data(), int(bad.size()));
        return;
    }

    // Hand cmangos's K to the world proxy: it is the key cmangos verifies the world-channel digest and
    // header cipher against, and it is available only here where hat-2 derived it.
    memcpy(g_sessionKey, cmangosK, sizeof g_sessionKey);
    g_sessionReady.store(true);
    log::line("[auth] world session key stored for account=%s", identity::user().c_str());

    const uint8_t* clientK = authprobe::clientSessionKey();
    if (!clientK) { log::line("[auth] azrt: client session key not captured -> cannot prove"); return; }
    uint8_t M2[20];
    srp::azrtFinish(A, M1, clientK, M2);

    // AZRT a3 (proof reply), opcode-0xA3 handler 0x14412ca7d: status(1) + M2[20] + u32 surveyId = exactly
    // 26 bytes (a trailing byte would be misread as the next opcode). M2 = SHA1(A, M1, K) over the client's
    // own session key, so its proof-verify accepts it. surveyId is 0x00010000 for AZRT (the value the client
    // expects to advance past the auth-success screen), not the classic 0.
    ByteWriter a3w;
    a3w.u8(op::azrt::kProof); a3w.u8(0x00);
    a3w.bytes(Bytes(M2, M2 + 20));
    a3w.u32(0x00010000);
    Bytes a3 = a3w.take();
    log::hex("[auth] ->a3(azrt)", a3.data(), int(a3.size()));
    net::sendAll(client, a3.data(), int(a3.size()));
    log::line("[auth] *** AZRT AUTH OK ***");

    // Past a3 the client is asynchronous: it requests the realm list (b0) on its own, and may emit a key-ack
    // (a6) once its own key derivation finishes. We drive no secure-channel handshake - the client already
    // holds its SRP session key - so each inbound frame is dispatched for what it is and only the realm
    // request is answered.
    for (;;) {
        n = recv(client, reinterpret_cast<char*>(buf), sizeof buf, 0);
        if (n <= 0) { log::line("[auth] azrt: auth socket closed (recv=%d err=%d)", n, WSAGetLastError()); return; }

        switch (buf[0]) {
        case op::azrt::kKeyAck:   // a6: the client's key ack; nothing to answer
            log::hex("[auth] <-a6", buf, n);
            break;
        case op::azrt::kRealmListReq: {   // b0: answer with the realm list so realm-select can proceed
            log::hex("[auth] <-b0(realm req)", buf, n);
            Bytes b1 = !realB1.empty() ? realB1 : synthRealmlist();   // the fetched realm list, else a local stand-in
            log::hex("[auth] ->b1(reply)", b1.data(), int(b1.size()));
            net::sendAll(client, b1.data(), int(b1.size()));
            g_realmReady.store(true);   // auth + realm exchange complete
            break;
        }
        case op::azrt::kKeyInstallAck:    // a9: key-install ack; unused, we install no world key
            log::hex("[auth] <-a9", buf, n);
            break;
        default:
            // Realm-select should emit its ChangeRealm/handoff request here (plaintext); capture it whole.
            log::hex("[auth] <-post-realm (handoff?)", buf, n);
            break;
        }
    }
}

void handleSession(SOCKET client) {
    uint8_t buf[4096];
    int n = recv(client, reinterpret_cast<char*>(buf), sizeof buf, 0);
    if (n <= 0 || buf[0] != op::azrt::kSessionOpen) { closesocket(client); return; }
    log::hex("[auth] <-a0", buf, n);

    // One login: play the AZRT server directly. The client computes its real I while answering our a1
    // (captured by the identity hook), and azrtServe validates it against cmangos before completing auth
    // - so no relay pass is needed just to capture I, yet unknown accounts are still rejected.
    azrtServe(client);
    closesocket(client);
}

} // namespace uoa::auth
