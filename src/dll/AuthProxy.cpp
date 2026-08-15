#include "AuthProxy.h"
#include "ByteBuffer.h"
#include "Sha1.h"
#include "Net.h"
#include "Settings.h"
#include "Config.h"
#include "Log.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>

namespace uoa::auth {
namespace {

// mangos WindowsHash(5875): the realmd version check expects crc_hash = SHA1(A || this).
const uint8_t kWindowsHash5875[20] = {
    0x95, 0xED, 0xB2, 0x7C, 0x78, 0x23, 0xB3, 0x63, 0xCB, 0xDD,
    0xAB, 0x56, 0xA3, 0x92, 0xE7, 0xCB, 0x73, 0xFC, 0xCA, 0x20,
};

// Client login-start "a0" -> realmd logon challenge (0x00).
Bytes toRealmdChallenge(const uint8_t* a0) {
    uint8_t nameLen = a0[27];
    std::string account(reinterpret_cast<const char*>(a0) + 28, nameLen);
    if (size_t z = account.find('\0'); z != std::string::npos) account.resize(z);
    for (char& c : account) c = char(toupper((unsigned char)c));

    ByteWriter body;
    body.text("WoW");  body.u8(0);              // "WoW\0"
    body.u8(1); body.u8(12); body.u8(1);        // game version 1.12.1
    body.u16(config::kBuild);
    body.text("68x"); body.u8(0);               // platform "x86" (reversed)
    body.text("niW"); body.u8(0);               // os "Win" (reversed)
    body.text("SUne");                          // locale "enUS" (reversed)
    body.u32(0);                                // timezone bias
    body.u8(127); body.u8(0); body.u8(0); body.u8(1);   // client ip
    body.u8(uint8_t(account.size()));
    body.text(account.c_str());

    ByteWriter pkt;
    pkt.u8(0x00); pkt.u8(0x08);                 // logon challenge, protocol 8
    pkt.u16(uint16_t(body.size()));
    pkt.bytes(body.data());
    return pkt.take();
}

// realmd logon challenge -> client "a1" (B | N | salt | g, 0).
Bytes toClientChallenge(const uint8_t* data, int len) {
    ByteReader r(data, len);
    r.u8();                       // cmd
    r.u8();                       // error
    uint8_t result = r.u8();
    if (result != 0x00)
        return { 0xa1, result, 0x00, 0x00 };

    Bytes    B    = r.take(32);
    r.u8();                       // g length
    uint8_t  g    = r.u8();
    r.u8();                       // N length
    Bytes    N    = r.take(32);
    Bytes    salt = r.take(32);

    ByteWriter body;
    body.bytes(B);
    body.bytes(N);
    body.bytes(salt);
    body.u8(g);
    body.u8(0);

    ByteWriter pkt;
    pkt.u8(0xa1); pkt.u8(0x00);
    pkt.u16(0x0096);   // 150: satisfies both the 130 and 150 thresholds
    pkt.bytes(body.data());
    return pkt.take();
}

// Client proof "a2" -> realmd logon proof (0x01) with a recomputed crc_hash.
Bytes toRealmdProof(const uint8_t* data, int len) {
    ByteReader r(data, len);
    r.u8();                       // cmd
    r.skip(2);
    Bytes A  = r.take(32);
    Bytes M1 = r.take(20);

    Sha1 sha;
    sha.update(A.data(), A.size());
    sha.update(kWindowsHash5875, sizeof kWindowsHash5875);
    uint8_t crc[20];
    sha.finish(crc);

    ByteWriter pkt;
    pkt.u8(0x01);
    pkt.bytes(A);
    pkt.bytes(M1);
    pkt.bytes(crc, sizeof crc);
    pkt.u8(0);                    // numkeys
    pkt.u8(0);                    // flags
    return pkt.take();
}

// realmd logon proof reply -> client "a3".
Bytes toClientProof(const uint8_t* data, int len) {
    ByteReader r(data, len);
    r.u8();                       // cmd
    uint8_t error = r.u8();
    if (error != 0x00) {
        Bytes e = { 0xa3, error };
        e.resize(26, 0);
        return e;
    }
    Bytes M2 = r.take(20);

    ByteWriter pkt;
    pkt.u8(0xa3); pkt.u8(0x00);
    pkt.bytes(M2);
    pkt.u8(0x00); pkt.u8(0x00); pkt.u8(0x01); pkt.u8(0x00);
    return pkt.take();
}

// realmd realmlist (0x10) -> client "b1", advertising the world proxy as the realm address.
Bytes toClientRealmlist(const uint8_t* data, int len) {
    if (len < 24) return {};      // too short to hold a realm; caller falls back

    ByteReader r(data, len);
    r.skip(8);                    // cmd + size + uint32 + realm count
    Bytes       icon       = r.take(4);
    uint8_t     flags      = r.u8();
    std::string name       = r.cstr();
    r.cstr();                     // realmd-advertised address (discarded)
    Bytes       population = r.take(4);
    uint8_t     chars      = r.u8();
    uint8_t     timezone   = r.u8();
    uint8_t     id         = r.u8();

    ByteWriter body;
    body.u32(0);                  // unknown
    body.u8(0x01);                // one realm
    body.bytes(icon);
    body.u8(flags);
    body.cstr(name);
    body.cstr(config::kWorldAddr);
    body.bytes(population);
    body.u8(chars);
    body.u8(timezone);
    body.u8(id);
    body.u8(0x02); body.u8(0x00); body.u8(0x02); body.u8(0x00);

    ByteWriter pkt;
    pkt.u8(0xb1);
    pkt.u16(uint16_t(body.size()));
    pkt.bytes(body.data());
    return pkt.take();
}

} // namespace

void handleSession(SOCKET client) {
    SOCKET realmd = net::dial(settings().forwardHost.c_str(), config::kRealmdPort);
    if (realmd == INVALID_SOCKET) {
        log::line("[auth] realmd unreachable");
        closesocket(client);
        return;
    }

    auto close = [&] { closesocket(client); closesocket(realmd); };
    uint8_t buf[4096];

    // a0 -> logon challenge
    int n = recv(client, reinterpret_cast<char*>(buf), sizeof buf, 0);
    if (n <= 0 || buf[0] != 0xa0) { close(); return; }
    log::hex("[auth] <-a0", buf, n);
    Bytes challenge = toRealmdChallenge(buf);
    net::sendAll(realmd, challenge.data(), int(challenge.size()));

    // logon challenge reply -> a1
    uint8_t chal[256];
    int chalLen = net::recvExact(realmd, chal, 119);
    log::hex("[auth] realmd-chal", chal, chalLen);
    Bytes a1 = toClientChallenge(chal, chalLen);
    log::hex("[auth] ->a1", a1.data(), int(a1.size()));
    net::sendAll(client, a1.data(), int(a1.size()));
    if (a1[1] != 0x00) { close(); return; }

    // a2 -> logon proof
    n = recv(client, reinterpret_cast<char*>(buf), sizeof buf, 0);
    if (n <= 0 || buf[0] != 0xa2) { close(); return; }
    log::hex("[auth] <-a2", buf, n);
    Bytes proof = toRealmdProof(buf, n);
    net::sendAll(realmd, proof.data(), int(proof.size()));

    // logon proof reply -> a3
    uint8_t proofReply[64];
    int replyLen = net::recvExact(realmd, proofReply, 2);
    if (replyLen >= 2 && proofReply[1] == 0)
        replyLen += net::recvExact(realmd, proofReply + 2, 24);
    log::hex("[auth] realmd-proof", proofReply, replyLen);
    Bytes a3 = toClientProof(proofReply, replyLen);
    log::hex("[auth] ->a3", a3.data(), int(a3.size()));
    net::sendAll(client, a3.data(), int(a3.size()));
    if (a3[1] != 0x00) { close(); return; }
    log::line("[auth] *** AUTH OK ***");

    // b0 -> realmlist
    n = recv(client, reinterpret_cast<char*>(buf), sizeof buf, 0);
    if (n <= 0 || buf[0] != 0xb0) { close(); return; }
    uint8_t request[5] = { 0x10, 0, 0, 0, 0 };
    net::sendAll(realmd, request, sizeof request);

    uint8_t list[4096];
    int listLen = net::recvExact(realmd, list, 3);
    int payload = list[1] | (list[2] << 8);
    listLen += net::recvExact(realmd, list + 3, payload);
    log::hex("[auth] realmd-realmlist", list, listLen);

    Bytes b1 = toClientRealmlist(list, listLen);
    if (b1.empty()) {              // fallback: forward the realm list unchanged
        b1.assign(list, list + listLen);
        b1[0] = 0xb1;
    }
    log::hex("[auth] ->b1", b1.data(), int(b1.size()));
    net::sendAll(client, b1.data(), int(b1.size()));
    log::line("[auth] realmlist sent -> %s", config::kWorldAddr);

    close();
}

} // namespace uoa::auth
