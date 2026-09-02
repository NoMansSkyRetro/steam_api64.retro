// SteamStub (Steam DRM wrapper, variant 3.1 x64) in-memory unwrap.
//
// The wrapper leaves the game's .text section AES-encrypted on disk and puts its
// own loader at the entry point. That loader talks to steamclient64.dll directly,
// so it cannot be satisfied from steam_api64.dll. Instead we do what the loader
// would do on success: decrypt .text with the key that sits in the stub header
// and continue at the original entry point. Same maths as Steamless, done at
// load time instead of on disk.
#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <string.h>
#pragma comment(lib, "bcrypt.lib")

void retro_log(const char* fmt, ...);

#pragma pack(push, 1)
struct StubHeader {                 // 0xF0 bytes, XOR-chained, sits right before the entry point
    uint32_t xorKey, signature;     // signature 0xC0DEC0DF once decoded
    uint64_t imageBase, entryPoint;
    uint32_t bindOffset, unk0;
    uint64_t oep;                   // original entry point (RVA)
    uint32_t unk1, payloadSize, drmpOffset, drmpSize, appId, flags, bindVSize, unk2;
    uint64_t codeVA, codeRawSize;   // .text RVA and raw size
    uint8_t  aesKey[32], aesIV[16], stolen[16];   // stolen = first 16 bytes of the encrypted section
    uint32_t encKeys[4], unk3[8];
    uint64_t rva[5];
};
#pragma pack(pop)
static_assert(sizeof(StubHeader) == 0xF0, "stub header layout");

enum { FLAG_NO_ENCRYPTION = 0x04 };

static uint8_t*   g_base;
static StubHeader g_hdr;
static void*      g_oep;
static void     (*g_after)();   // run once the code section is readable

static void steam_xor(uint8_t* d, size_t n) {   // key = first dword, then each dword is XORed with the previous ciphertext dword
    uint32_t key; memcpy(&key, d, 4);
    for (size_t i = 4; i < n; i += 4) {
        uint32_t v; memcpy(&v, d + i, 4);
        uint32_t o = v ^ key; memcpy(d + i, &o, 4);
        key = v;
    }
}

// AES-256-CBC, no padding. Windows CNG so there is nothing to ship.
static bool aes_cbc_decrypt(const uint8_t key[32], uint8_t iv[16], const uint8_t* in, uint8_t* out, size_t n) {
    BCRYPT_ALG_HANDLE alg = 0; BCRYPT_KEY_HANDLE k = 0; ULONG got = 0; bool ok = false;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, 0, 0) == 0
        && BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0) == 0
        && BCryptGenerateSymmetricKey(alg, &k, 0, 0, (PUCHAR)key, 32, 0) == 0
        && BCryptDecrypt(k, (PUCHAR)in, (ULONG)n, 0, iv, 16, out, (ULONG)n, &got, 0) == 0 && got == n)
        ok = true;
    if (k) BCryptDestroyKey(k);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

static bool unwrap() {
    if (g_hdr.flags & FLAG_NO_ENCRYPTION) return true;
    uint8_t* text = g_base + g_hdr.codeVA;
    size_t n = (size_t)g_hdr.codeRawSize;
    // The IV in the header is itself AES-encrypted with the key; ECB-decrypt it (CBC with a zero IV is the same for one block).
    uint8_t zero[16] = {0}, iv[16];
    if (!aes_cbc_decrypt(g_hdr.aesKey, zero, g_hdr.aesIV, iv, 16)) return false;
    // Ciphertext = stolen bytes + section contents shifted by 16. Decrypt straight into the mapped section.
    uint8_t* src = (uint8_t*)VirtualAlloc(0, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!src) return false;
    memcpy(src, g_hdr.stolen, 16);
    memcpy(src + 16, text, n - 16);
    DWORD old;
    bool ok = VirtualProtect(text, n, PAGE_EXECUTE_READWRITE, &old) && aes_cbc_decrypt(g_hdr.aesKey, iv, src, text, n);
    VirtualProtect(text, n, PAGE_EXECUTE_READ, &old);
    FlushInstructionCache(GetCurrentProcess(), text, n);
    VirtualFree(src, 0, MEM_RELEASE);
    return ok;
}

// The 12-byte jump planted at the stub entry lands here, with the loader's registers intact (RCX = PEB).
extern "C" int retro_entry(void* peb) {
    if (!unwrap()) {
        MessageBoxA(0, "Could not decrypt the game executable.", "steam_api64.retro", MB_ICONERROR);
        TerminateProcess(GetCurrentProcess(), 1);
    }
    retro_log("code section decrypted, continuing at original entry point %p", g_oep);
    if (g_after) g_after();
    return ((int (*)(void*))g_oep)(peb);
}

// Called from DllMain, before the exe entry point runs. Returns false when the exe has no SteamStub
// (the caller then runs `after` itself, since the code is already readable).
bool steamstub_prepare(HMODULE exe, void (*after)()) {
    g_base = (uint8_t*)exe;
    g_after = after;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(g_base + ((IMAGE_DOS_HEADER*)g_base)->e_lfanew);
    uint8_t* ep = g_base + nt->OptionalHeader.AddressOfEntryPoint;
    memcpy(&g_hdr, ep - sizeof g_hdr, sizeof g_hdr);
    steam_xor((uint8_t*)&g_hdr, sizeof g_hdr);
    if (g_hdr.signature != 0xC0DEC0DF) return false;
    if (g_hdr.codeVA + g_hdr.codeRawSize > nt->OptionalHeader.SizeOfImage || g_hdr.codeRawSize < 16 || (g_hdr.codeRawSize & 15)) {
        retro_log("SteamStub header found but code section fields look wrong; leaving the stub alone");
        return false;
    }
    g_oep = g_base + g_hdr.oep;
    retro_log("SteamStub 3.1: appid %u flags 0x%x oep 0x%llx text 0x%llx+0x%llx", g_hdr.appId, g_hdr.flags, g_hdr.oep, g_hdr.codeVA, g_hdr.codeRawSize);
    uint8_t jmp[12] = {0x48, 0xB8};                   // mov rax, retro_entry ; jmp rax
    void* target = (void*)&retro_entry;
    memcpy(jmp + 2, &target, 8);
    jmp[10] = 0xFF; jmp[11] = 0xE0;
    DWORD old;
    VirtualProtect(ep, sizeof jmp, PAGE_EXECUTE_READWRITE, &old);
    memcpy(ep, jmp, sizeof jmp);
    VirtualProtect(ep, sizeof jmp, old, &old);
    return true;
}
