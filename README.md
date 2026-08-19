# Unreal-Open-Azeroth

An injected DLL that removes the **server-side licence layer** of the "Unreal Azeroth"
client so it can authenticate and list characters against a **local server you control**,
instead of only the licensed servers the stock client is locked to.

The client ships with a custom account handshake (an SRP variant) and per-connection
canaries that gate it to specific servers. Unreal-Open-Azeroth redirects the client's
realmd/world connections to in-process proxies, re-keys those canaries onto keys we hold,
and translates the account handshake to a stock **mangos 1.12** login. The result: the
client reaches its own **character-select screen** against a local realm.

For local research on servers you own or are authorized to use.

## Scope

This project targets the **licence layer only**, the two surfaces it unlocks are:

1. **Account connection**, the auth handshake (realmd), including the client's SRP
   variant and its canary validation.
2. **Character list**, the world-channel char-enum, reshaped to the client's record
   layout so the character-select screen populates.

Everything past character select (entering the world, movement, rendering, gameplay) is
**out of scope and not implemented**. It is a different problem, a full world-protocol
translation between the client and a mangos server, and this project deliberately does
not attempt it. Anyone who wants that layer can build it on top; the hooks and the world
proxy are here, but the mission stops at defeating the licence.

## How it works

- **Injection.** A one-time patch on the client executable adds the DLL to its imports so
  the loader maps it at startup (`src/patcher/`).
- **Connection redirect.** The DLL hooks `connect()` and points the client's realmd and
  world sockets at internal proxies on loopback.
- **Auth translation.** The auth proxy speaks the client's SRP variant on one side and a
  stock mangos logon on the other, recomputing the proofs so both ends agree.
- **Canary re-key.** The client's connection canaries are re-keyed onto keys the proxy
  holds, so the client validates against us instead of a licensed server.
- **Character list.** On the world channel, the char-enum reply is reshaped into the
  record layout the client expects, so character-select populates.

## Layout

```
src/dll/            the injected DLL (UnrealOpenAzeroth.dll)
src/patcher/        the one-time executable patch that adds the DLL import
third_party/minhook inline hooking library
```

## Build

Open an **x64 Native Tools Command Prompt for VS**, then:

```
build.bat
```

Produces `UnrealOpenAzeroth.dll` and `patcher.exe`. CMake also works:

```
cmake -B build -A x64
cmake --build build --config Release
```

## Install

1. Restore the client to a pristine state (copy `Azeroth-Win64-Shipping.exe.orig` over
   `Azeroth-Win64-Shipping.exe`) so no previous import remains.
2. Copy `UnrealOpenAzeroth.dll` next to the exe.
3. Run `patcher.exe` from the exe folder. It adds the DLL import and saves a pristine
   backup as `Azeroth-Win64-Shipping.exe.orig` on first run.
4. Launch the client. Progress is written to `UnrealOpenAzeroth.log` next to the exe.

## Config (next to the exe)

`realmlist.wtf`, the local server the proxies forward to:

```
set realmlist 127.0.0.1
```
