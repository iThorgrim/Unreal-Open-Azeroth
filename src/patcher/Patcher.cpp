// patcher.cpp - applies the two exe modifications for UnrealOpenAzeroth:
//   1. neutralize the SRP pepper (the client then speaks standard SRP6)
//   2. import UnrealOpenAzeroth.dll so the loader loads it at startup
// Both steps are idempotent. A pristine copy is saved as <exe>.orig on first run.
//
// Usage: patcher.exe [path\to\Azeroth-Win64-Shipping.exe]

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

static const char* kExeDefault = "Azeroth-Win64-Shipping.exe";
static const char* kDllName    = "UnrealOpenAzeroth.dll";
static const char* kAnchor     = "uoa_anchor";
static const char* kPepperTail = "ZRT-PEPPER-v1";   // preceded by the 'A' of the full pepper literal

static uint32_t alignUp(uint32_t value, uint32_t align) {
    return (value + align - 1) & ~(align - 1);
}

static bool neutralizePepper(std::vector<uint8_t>& buf) {
    auto dos = (IMAGE_DOS_HEADER*)buf.data();
    auto nt  = (IMAGE_NT_HEADERS64*)(buf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { printf("[patch] not a PE\n"); return false; }
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    int sectionCount = nt->FileHeader.NumberOfSections;
    uint64_t imageBase = nt->OptionalHeader.ImageBase;

    auto offToVa = [&](size_t off) -> uint64_t {
        for (int i = 0; i < sectionCount; ++i) {
            uint32_t p = sections[i].PointerToRawData;
            if (off >= p && off < p + sections[i].SizeOfRawData)
                return imageBase + sections[i].VirtualAddress + (uint32_t)(off - p);
        }
        return 0;
    };

    // The pepper literal is "A" + kPepperTail; the referenced address is the leading 'A'.
    size_t tailLen = strlen(kPepperTail);
    size_t pepOff = 0;
    for (size_t i = 1; i + tailLen <= buf.size(); ++i)
        if (memcmp(&buf[i], kPepperTail, tailLen) == 0) { pepOff = i - 1; break; }
    if (!pepOff) { printf("[patch] pepper marker not found (exe changed?)\n"); return false; }
    uint64_t pepVa = offToVa(pepOff);

    // Find `lea r8, [rip -> pepper]` (4C 8D 05 disp32); the `mov r9d, imm32` (41 B9 imm) six bytes
    // before it holds the pepper source length. Zero that immediate.
    for (size_t l = 6; l + 7 <= buf.size(); ++l) {
        if (buf[l] != 0x4C || buf[l + 1] != 0x8D || buf[l + 2] != 0x05) continue;
        int32_t disp; memcpy(&disp, &buf[l + 3], 4);
        uint64_t leaVa = offToVa(l);
        if (!leaVa || leaVa + 7 + (int64_t)disp != pepVa) continue;

        size_t m = l - 6;   // the preceding `mov r9d, imm32`
        if (buf[m] != 0x41 || buf[m + 1] != 0xB9 || buf[m + 4] != 0x00 || buf[m + 5] != 0x00) continue;
        if (buf[m + 2] == 0x00) { printf("[patch] pepper already neutralized\n"); return true; }
        if (buf[m + 2] != 0x0F) continue;

        buf[m + 2] = 0x00;   // pepper source length 15 -> 0
        printf("[patch] pepper neutralized (r9d 15->0 at file 0x%zx)\n", m + 2);
        return true;
    }
    printf("[patch] pepper builder site not found (concat changed?)\n");
    return false;
}

// Adds an import descriptor for kDllName!kAnchor in a fresh .uoa section.
static bool addImport(std::vector<uint8_t>& buf) {
    auto dos = (IMAGE_DOS_HEADER*)buf.data();
    auto nt  = (IMAGE_NT_HEADERS64*)(buf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        printf("[patch] not a PE64\n");
        return false;
    }

    IMAGE_OPTIONAL_HEADER64& oh = nt->OptionalHeader;
    uint32_t fileAlign = oh.FileAlignment;
    uint32_t sectAlign = oh.SectionAlignment;
    int sectionCount = nt->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);

    auto rvaToOffset = [&](uint32_t rva) -> uint32_t {
        for (int i = 0; i < sectionCount; ++i) {
            uint32_t start = sections[i].VirtualAddress;
            if (rva >= start && rva < start + sections[i].SizeOfRawData)
                return sections[i].PointerToRawData + (rva - start);
        }
        return 0;
    };

    // Existing descriptors; stop if we are already imported.
    uint32_t importRva = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    auto oldDesc = (IMAGE_IMPORT_DESCRIPTOR*)(buf.data() + rvaToOffset(importRva));
    int descCount = 0;
    while (oldDesc[descCount].Name || oldDesc[descCount].FirstThunk) ++descCount;
    for (int i = 0; i < descCount; ++i) {
        const char* name = (const char*)(buf.data() + rvaToOffset(oldDesc[i].Name));
        if (_stricmp(name, kDllName) == 0) { printf("[patch] already imported\n"); return true; }
    }

    uint32_t headerEnd = (uint32_t)((uint8_t*)(sections + sectionCount) - buf.data());
    if (headerEnd + sizeof(IMAGE_SECTION_HEADER) > oh.SizeOfHeaders) {
        printf("[patch] no room for a section header\n");
        return false;
    }

    // Geometry of the new section.
    uint32_t maxRva = 0, maxRaw = 0;
    for (int i = 0; i < sectionCount; ++i) {
        uint32_t virtualSize = sections[i].Misc.VirtualSize ? sections[i].Misc.VirtualSize : sections[i].SizeOfRawData;
        uint32_t endRva = sections[i].VirtualAddress + alignUp(virtualSize, sectAlign);
        uint32_t endRaw = sections[i].PointerToRawData + sections[i].SizeOfRawData;
        if (endRva > maxRva) maxRva = endRva;
        if (endRaw > maxRaw) maxRaw = endRaw;
    }
    uint32_t newRva = alignUp(maxRva, sectAlign);
    uint32_t newRaw = alignUp((uint32_t)buf.size(), fileAlign);

    // Blob layout (offsets relative to newRva): descriptors | INT | IAT | import-by-name | dll-name.
    uint32_t descBytes = (uint32_t)((descCount + 2) * sizeof(IMAGE_IMPORT_DESCRIPTOR));
    uint32_t offInt  = alignUp(descBytes, 8);
    uint32_t offIat  = offInt + 2 * sizeof(IMAGE_THUNK_DATA64);
    uint32_t offName = offIat + 2 * sizeof(IMAGE_THUNK_DATA64);
    uint32_t nameBytes = alignUp(2 + (uint32_t)strlen(kAnchor) + 1, 2);
    uint32_t offDllName = offName + nameBytes;
    uint32_t blobSize = offDllName + (uint32_t)strlen(kDllName) + 1;

    std::vector<uint8_t> blob(blobSize, 0);
    auto desc = (IMAGE_IMPORT_DESCRIPTOR*)blob.data();
    memcpy(desc, oldDesc, descCount * sizeof(IMAGE_IMPORT_DESCRIPTOR));
    desc[descCount].OriginalFirstThunk = newRva + offInt;
    desc[descCount].Name       = newRva + offDllName;
    desc[descCount].FirstThunk = newRva + offIat;

    auto intThunk = (IMAGE_THUNK_DATA64*)(blob.data() + offInt);
    auto iatThunk = (IMAGE_THUNK_DATA64*)(blob.data() + offIat);
    intThunk[0].u1.AddressOfData = newRva + offName;
    iatThunk[0].u1.AddressOfData = newRva + offName;

    memcpy(blob.data() + offName + 2, kAnchor, strlen(kAnchor) + 1);   // IMAGE_IMPORT_BY_NAME (hint=0)
    memcpy(blob.data() + offDllName, kDllName, strlen(kDllName) + 1);

    // Append the blob padded to file alignment.
    buf.resize(newRaw);
    uint32_t rawSize = alignUp(blobSize, fileAlign);
    std::vector<uint8_t> raw(rawSize, 0);
    memcpy(raw.data(), blob.data(), blobSize);
    buf.insert(buf.end(), raw.begin(), raw.end());

    // Pointers may have moved after the resize.
    dos = (IMAGE_DOS_HEADER*)buf.data();
    nt  = (IMAGE_NT_HEADERS64*)(buf.data() + dos->e_lfanew);
    sections = IMAGE_FIRST_SECTION(nt);

    IMAGE_SECTION_HEADER& section = sections[sectionCount];
    memset(&section, 0, sizeof section);
    memcpy(section.Name, ".uoa", 4);
    section.Misc.VirtualSize = blobSize;
    section.VirtualAddress   = newRva;
    section.SizeOfRawData    = rawSize;
    section.PointerToRawData = newRaw;
    section.Characteristics  = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    nt->FileHeader.NumberOfSections++;
    nt->OptionalHeader.SizeOfImage = alignUp(newRva + blobSize, sectAlign);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = newRva;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = descBytes;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
    nt->OptionalHeader.CheckSum = 0;

    printf("[patch] import added (.uoa section, +%u bytes)\n", blobSize);
    return true;
}

int main(int argc, char** argv) {
    const char* path = kExeDefault;
    bool doPepper = true;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--no-pepper") == 0) doPepper = false;
        else path = argv[i];
    }

    FILE* f = fopen(path, "rb");
    if (!f) { printf("[patch] cannot open %s\n", path); return 1; }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> buf(size);
    fread(buf.data(), 1, size, f);
    fclose(f);

    std::string backup = std::string(path) + ".orig";
    if (GetFileAttributesA(backup.c_str()) == INVALID_FILE_ATTRIBUTES) {
        if (FILE* b = fopen(backup.c_str(), "wb")) {
            fwrite(buf.data(), 1, buf.size(), b);
            fclose(b);
            printf("[patch] backup -> %s\n", backup.c_str());
        }
    }

    bool ok = doPepper ? neutralizePepper(buf) : (printf("[patch] pepper left intact (--no-pepper)\n"), true);
    ok = addImport(buf) && ok;
    if (!ok) { printf("[patch] aborted, exe not written\n"); return 1; }

    FILE* out = fopen(path, "wb");
    if (!out) { printf("[patch] write failed (exe locked / client running?)\n"); return 1; }
    fwrite(buf.data(), 1, buf.size(), out);
    fclose(out);
    printf("[patch] done. Place %s next to the exe.\n", kDllName);
    return 0;
}
