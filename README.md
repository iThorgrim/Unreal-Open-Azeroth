# Unreal-Open-Azeroth

Local interop layer for the Unreal "Azeroth" client. An injected DLL redirects the
client's realmd/world connections to internal proxies, translates the auth handshake
to a stock mangos 1.12 server, and can override the client's Discord Rich Presence.

For local research on servers you own or are authorized to use.

## Layout

```
src/dll/            the injected DLL (UnrealOpenAzeroth.dll)
src/patcher/        Patcher.cpp: strips the SRP pepper and imports the DLL
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

1. Restore the client to a pristine state (copy `Azeroth-Win64-Shipping.exe.orig`
   over `Azeroth-Win64-Shipping.exe`) so no previous import remains.
2. Copy `UnrealOpenAzeroth.dll` next to the exe.
3. Run `patcher.exe` from the exe folder. It strips the SRP pepper and adds the DLL
   import. A pristine backup is saved as `Azeroth-Win64-Shipping.exe.orig` on first run.
4. Launch the client. Progress is written to `UnrealOpenAzeroth.log` next to the exe.

## Config files (next to the exe)

`realmlist.wtf` - the server the proxies forward to:

```
set realmlist 127.0.0.1
```

`discord.wtf` - Rich Presence override (any missing key keeps the game's value):

```
details WarcraftXL
state   Interop research
type    playing
# application_id 123456789012345678   # optional: your Discord app -> changes the title
```
