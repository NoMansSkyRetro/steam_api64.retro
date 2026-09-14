// steam_api64.retro: stand-in steam_api64.dll for the legacy No Man's Sky builds
// (1.09.1 through 1.38 on Steam). Unwraps the SteamStub DRM in memory (see
// steamstub.cpp) and answers the handful of Steamworks calls these builds make.
#include <windows.h>
#include <winhttp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <string>
#include <map>
#include <vector>
#include <utility>
#pragma comment(lib, "winhttp.lib")

bool steamstub_prepare(HMODULE exe, void (*after)());   // steamstub.cpp

static const uint32_t APPID = 275850;
static const uint32_t LAST_SUPPORTED_BUILD = 0x59ce2f3c;   // PE timestamp of the 1.38 (Atlas Rises) NMS.exe; anything newer is refused

// ---- logging: create an empty steam_api64.retro.log next to the DLL to enable ----
static char  g_dir[MAX_PATH];
static FILE* g_log;
void retro_log(const char* fmt, ...) {
    if (!g_log) return;
    va_list ap; va_start(ap, fmt); vfprintf(g_log, fmt, ap); va_end(ap);
    fputc('\n', g_log); fflush(g_log);
}

// ---- settings: steam_api64.txt next to the DLL, written with defaults on first run ----
// steamid is what the game is told its Steam ID is; savesteamid is the one the save system uses
// instead (see patch_save_id). Both only have to be numbers.
static uint64_t    g_steamid, g_saveid;
static std::string g_name = "Player", g_lang = "english";
static bool        g_modwarn;                                                  // disablemodwarning=
static struct { bool on, https; wchar_t host[256]; INTERNET_PORT port; } g_srv;   // discoveriesserver=
static ULONGLONG   g_start;
static std::map<std::string, bool> g_ach;   // ponytail: achievements live for the session only, add a file if anyone misses them

static const struct { uint32_t timestamp; uint64_t steamid; } DEFAULT_IDS[] = {   // NMS.exe PE timestamp -> version number, so each build gets its own save folder
    {0x57ff70ca, 109}, {0x584983de, 113}, {0x58d42a08, 124}, {0x59ce2f3c, 138},
};

static void set_server(const char* v) {   // [http://|https://]host[:port]
    g_srv.https = !_strnicmp(v, "https://", 8);
    if (g_srv.https) v += 8; else if (!_strnicmp(v, "http://", 7)) v += 7;
    char host[256]; strncpy(host, v, sizeof host - 1); host[sizeof host - 1] = 0;
    char* end = strpbrk(host, "/ \t"); if (end) *end = 0;
    g_srv.port = g_srv.https ? 443 : 80;
    char* colon = strrchr(host, ':'); if (colon) { *colon = 0; g_srv.port = (INTERNET_PORT)atoi(colon + 1); }
    if (!*host) return;
    MultiByteToWideChar(CP_UTF8, 0, host, -1, g_srv.host, 256);
    g_srv.on = true;
}

static void load_settings(uint32_t exe_timestamp) {
    for (auto& d : DEFAULT_IDS) if (d.timestamp == exe_timestamp) g_steamid = d.steamid;
    char p[MAX_PATH]; snprintf(p, sizeof p, "%s\\steam_api64.txt", g_dir);
    FILE* f = fopen(p, "r");
    if (!f) {
        if ((f = fopen(p, "w")) != 0) {
            fprintf(f, "# steam_api64.retro settings, see README.md\n"
                       "steamid=%llu\nname=%s\nlanguage=%s\n"
                       "# the save folder and the save encryption use this ID instead, so saves stay put when steamid changes\n"
                       "savesteamid=%llu\n"
                       "# true skips the mods-enabled warning screen at boot (1.13 and later)\ndisablemodwarning=false\n"
                       "# http://host:port or https://host sends the discoveries traffic to that server instead of Hello Games\ndiscoveriesserver=\n",
                    g_steamid, g_name.c_str(), g_lang.c_str(), g_steamid);
            fclose(f);
        }
        g_saveid = g_steamid;
        return;
    }
    char line[512];
    while (fgets(line, sizeof line, f)) {
        char* v = strchr(line, '=');
        if (!v || line[0] == '#') continue;
        *v++ = 0;
        size_t n = strlen(v);
        while (n && (v[n - 1] == '\n' || v[n - 1] == '\r' || v[n - 1] == ' ')) v[--n] = 0;
        if (!n) continue;
        if (!strcmp(line, "steamid")) g_steamid = strtoull(v, 0, 10);
        else if (!strcmp(line, "savesteamid")) g_saveid = strtoull(v, 0, 10);
        else if (!strcmp(line, "name")) g_name = v;
        else if (!strcmp(line, "language")) g_lang = v;
        else if (!strcmp(line, "disablemodwarning")) g_modwarn = !_stricmp(v, "true") || !strcmp(v, "1");
        else if (!strcmp(line, "discoveriesserver")) set_server(v);
    }
    fclose(f);
    if (!g_saveid) g_saveid = g_steamid;   // no savesteamid line: saves stay where they always were
}

// ---- mod warning: the pak loader sets a "mods loaded" byte after mounting PCBANKS/MODS, and the boot
// screens show the warning only when it is set. Flip the stored value from 1 to 0. One hit in every
// build that has the mod system (1.13+); 1.09.1 has none, so nothing to do there. ----
static void patch_mod_warning() {
    if (!g_modwarn) return;
    static const uint8_t sig[] = {0x49, 0x8B, 0x06, 0xC6, 0x80, 0x92, 0x26, 0x00, 0x00, 0x01};   // mov rax,[r14]; mov byte [rax+0x2692],1
    uint8_t* b = (uint8_t*)GetModuleHandleA(0);
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(b + ((IMAGE_DOS_HEADER*)b)->e_lfanew);
    IMAGE_SECTION_HEADER* s = IMAGE_FIRST_SECTION(nt);
    uint8_t* hit = 0; int hits = 0;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, s++) {
        if (!(s->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        for (uint8_t* p = b + s->VirtualAddress, *e = p + s->Misc.VirtualSize - sizeof sig; p <= e; p++)
            if (*p == sig[0] && !memcmp(p, sig, sizeof sig)) { hit = p; hits++; }
    }
    if (hits != 1) { retro_log("mod warning: signature found %d times, leaving the game alone", hits); return; }
    DWORD old;
    VirtualProtect(hit + 9, 1, PAGE_EXECUTE_READWRITE, &old);
    hit[9] = 0;
    VirtualProtect(hit + 9, 1, old, &old);
    retro_log("mod warning disabled, patched byte at %p", hit + 9);
}

// ---- save Steam ID: the game asks SteamUser::GetSteamID once for its save manager and keeps the
// answer, then uses it twice - to name the st_<id> save folder and as part of the key the save files
// are encrypted with. That ties a save to whatever ID was live when it was written, so saves cannot
// be carried between builds that run under different IDs. Every supported build reads that returned
// ID with the same instruction right after the call (call [rax+0x10]; mov rax,[rsp+disp8]), followed
// within a few bytes by the "an ID is present" byte going to +8 of the object being filled in, which
// no other GetSteamID call site does. Replacing that one load with a call returning savesteamid puts
// saves on their own ID and leaves every other use of the real one alone. One hit in 1.09.1 and 1.13
// (save manager and cache share a constructor), two in 1.24 and 1.38 (it is inlined into both). ----
static uint8_t* alloc_near(uint8_t* anchor) {   // the patch is a 5-byte call, so the trampoline has to be within 2GB
    for (uint64_t off = 0x10000; off < 0x20000000; off += 0x10000)
        for (int up = 0; up < 2; up++)
            if (void* p = VirtualAlloc(anchor + (up ? (int64_t)off : -(int64_t)off), 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))
                return (uint8_t*)p;
    return 0;
}

static void patch_save_id() {
    if (g_saveid == g_steamid) return;
    uint8_t* b = (uint8_t*)GetModuleHandleA(0);
    uint8_t* tramp = alloc_near(b);
    if (!tramp) { retro_log("save id: no free memory within reach of the exe, saves stay on steamid"); return; }
    tramp[0] = 0x48; tramp[1] = 0xB8; memcpy(tramp + 2, &g_saveid, 8); tramp[10] = 0xC3;   // mov rax, savesteamid ; ret

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(b + ((IMAGE_DOS_HEADER*)b)->e_lfanew);
    IMAGE_SECTION_HEADER* s = IMAGE_FIRST_SECTION(nt);
    int hits = 0;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, s++) {
        if (!(s->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        for (uint8_t* p = b + s->VirtualAddress, *e = p + s->Misc.VirtualSize - 24; p <= e; p++) {
            if (p[0] != 0xFF || p[1] != 0x50 || p[2] != 0x10) continue;                     // call [rax+0x10] -> GetSteamID
            if (p[3] != 0x48 || p[4] != 0x8B || p[5] != 0x44 || p[6] != 0x24) continue;     // mov rax,[rsp+disp8]
            bool save = false;
            for (int j = 8; j < 18 && !save; j++)                                           // mov byte [reg+8],1
                save = p[j] == 0xC6 && (p[j + 1] & 0xF8) == 0x40 && (p[j + 1] & 7) != 4 && p[j + 2] == 0x08 && p[j + 3] == 0x01;
            if (!save) continue;
            int64_t rel = tramp - (p + 8);
            if (rel != (int32_t)rel) continue;
            DWORD old;
            VirtualProtect(p + 3, 5, PAGE_EXECUTE_READWRITE, &old);
            p[3] = 0xE8; memcpy(p + 4, &rel, 4);                                            // call tramp
            VirtualProtect(p + 3, 5, old, &old);
            hits++;
        }
    }
    FlushInstructionCache(GetCurrentProcess(), 0, 0);
    retro_log("save id %llu: patched %d call site(s)", g_saveid, hits);
}

static void patch_code() { patch_mod_warning(); patch_save_id(); }   // both run once the code section is readable

// ---- discoveries server: the game authenticates against <env>-nms-auth.nomanssky.com and takes every
// other endpoint from the "routes" in that reply, so redirecting the auth connection is enough. Done by
// hooking the exe's WinHTTP imports; scheme and port follow the configured URL. ----
static HINTERNET (WINAPI *real_Connect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
static HINTERNET (WINAPI *real_OpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
static BOOL      (WINAPI *real_CloseHandle)(HINTERNET);
static HINTERNET g_redirected[16];

static bool hg_host(LPCWSTR h) {
    size_t n = wcslen(h);
    return (n >= 13 && !_wcsicmp(h + n - 13, L"nomanssky.com")) || wcsstr(h, L"hellogames") != 0;
}
static HINTERNET WINAPI my_Connect(HINTERNET session, LPCWSTR host, INTERNET_PORT port, DWORD reserved) {
    if (!hg_host(host)) return real_Connect(session, host, port, reserved);
    HINTERNET h = real_Connect(session, g_srv.host, g_srv.port, reserved);
    retro_log("discoveries: %ls:%u -> %ls:%u%s", host, port, g_srv.host, g_srv.port, h ? "" : " (WinHttpConnect failed)");
    for (auto& e : g_redirected) if (!e) { e = h; break; }
    return h;
}
static HINTERNET WINAPI my_OpenRequest(HINTERNET conn, LPCWSTR verb, LPCWSTR path, LPCWSTR ver, LPCWSTR referrer, LPCWSTR* accept, DWORD flags) {
    bool redirected = false;
    for (auto e : g_redirected) if (e && e == conn) redirected = true;
    if (!redirected) return real_OpenRequest(conn, verb, path, ver, referrer, accept, flags);
    flags = g_srv.https ? (flags | WINHTTP_FLAG_SECURE) : (flags & ~WINHTTP_FLAG_SECURE);
    HINTERNET h = real_OpenRequest(conn, verb, path, ver, referrer, accept, flags);
    if (h && g_srv.https) {   // community servers rarely have a certificate the game would accept
        DWORD f = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(h, WINHTTP_OPTION_SECURITY_FLAGS, &f, sizeof f);
    }
    retro_log("discoveries: %ls %ls", verb, path);
    return h;
}
static BOOL WINAPI my_CloseHandle(HINTERNET h) {
    for (auto& e : g_redirected) if (e == h) e = 0;
    return real_CloseHandle(h);
}

static void* hook_import(HMODULE mod, const char* dll, const char* fn, void* replacement) {
    uint8_t* b = (uint8_t*)mod;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(b + ((IMAGE_DOS_HEADER*)b)->e_lfanew);
    IMAGE_DATA_DIRECTORY& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    for (IMAGE_IMPORT_DESCRIPTOR* d = (IMAGE_IMPORT_DESCRIPTOR*)(b + dir.VirtualAddress); dir.VirtualAddress && d->Name; d++) {
        if (_stricmp((char*)(b + d->Name), dll)) continue;
        IMAGE_THUNK_DATA* names = (IMAGE_THUNK_DATA*)(b + d->OriginalFirstThunk);
        IMAGE_THUNK_DATA* iat = (IMAGE_THUNK_DATA*)(b + d->FirstThunk);
        for (; names->u1.AddressOfData; names++, iat++) {
            if (names->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
            if (strcmp(((IMAGE_IMPORT_BY_NAME*)(b + names->u1.AddressOfData))->Name, fn)) continue;
            void* orig = (void*)iat->u1.Function;
            DWORD old;
            VirtualProtect(&iat->u1.Function, sizeof(void*), PAGE_READWRITE, &old);
            iat->u1.Function = (ULONGLONG)replacement;
            VirtualProtect(&iat->u1.Function, sizeof(void*), old, &old);
            return orig;
        }
    }
    return 0;
}
static void hook_winhttp(HMODULE exe) {
    real_Connect     = (decltype(real_Connect))    hook_import(exe, "winhttp.dll", "WinHttpConnect",     (void*)&my_Connect);
    real_OpenRequest = (decltype(real_OpenRequest))hook_import(exe, "winhttp.dll", "WinHttpOpenRequest", (void*)&my_OpenRequest);
    real_CloseHandle = (decltype(real_CloseHandle))hook_import(exe, "winhttp.dll", "WinHttpCloseHandle", (void*)&my_CloseHandle);
    retro_log("discoveries server %ls:%u (%s): WinHTTP hooks %s", g_srv.host, g_srv.port, g_srv.https ? "https" : "http",
              real_Connect && real_OpenRequest && real_CloseHandle ? "installed" : "NOT installed, exe does not import WinHTTP by name");
}

// ---- callbacks ----
struct CCallbackBase { void** vt; uint8_t flags; int id; };   // vt[0] = Run(void* param)
static std::vector<CCallbackBase*> g_cbs;
static std::vector<std::pair<int, std::vector<uint8_t>>> g_pending;
static void post(int id, const void* data, size_t n) { g_pending.emplace_back(id, std::vector<uint8_t>((const uint8_t*)data, (const uint8_t*)data + n)); }

#pragma pack(push, 8)
struct UserStatsReceived_t          { uint64_t gameId; int result; uint64_t steamId; };                  // 1101
struct UserAchievementStored_t      { uint64_t gameId; bool group; char name[128]; uint32_t cur, max; }; // 1103
struct GetAuthSessionTicketResponse_t { uint32_t ticket; int result; };                                  // 163
#pragma pack(pop)

// ---- interfaces: a vtable of logging stubs per interface version, with the slots the game needs filled in ----
struct Iface { const char* name; void** obj; void* vt[128]; bool logged[128]; };   // the game's `this` is &obj, *this is the vtable
static Iface g_if[32];
static int   g_nif;
static std::map<std::string, Iface*> g_byname;

template<int N> static uint64_t slot_stub(void* self) {   // logs the first call of each slot so unhandled methods show up
    for (int i = 0; i < g_nif; i++)
        if (self == &g_if[i].obj && !g_if[i].logged[N]) { g_if[i].logged[N] = true; retro_log("%s slot %d not implemented, returning 0", g_if[i].name, N); }
    return 0;
}
template<int... I> static void fill(void** vt, std::integer_sequence<int, I...>) { void* t[] = {(void*)&slot_stub<I>...}; memcpy(vt, t, sizeof t); }
static Iface* make(const char* name) {
    Iface& f = g_if[g_nif++]; f.name = name; f.obj = f.vt;
    fill(f.vt, std::make_integer_sequence<int, 128>());
    return &f;
}
#define OBJ(f) ((void*)&(f)->obj)

// Method bodies. `self` is the interface `this`; struct returns arrive through a hidden pointer after it (MSVC x64).
static uint64_t    ret1(void*)                                   { return 1; }
static const char* ret_empty(void*)                              { return ""; }
static int         ret_m1(void*)                                 { return -1; }
template<int N> static void* zero_out(void*, void* out)          { memset(out, 0, N); return out; }
static uint64_t*   my_id(void*, uint64_t* out)                   { *out = g_steamid; return out; }
static const char* my_name(void*)                                { return g_name.c_str(); }
static const char* my_lang(void*)                                { return g_lang.c_str(); }
static uint32_t    appid(void*)                                  { return APPID; }
static uint32_t    secs_active(void*)                            { return (uint32_t)((GetTickCount64() - g_start) / 1000); }
static uint32_t    secs_up(void*)                                { return (uint32_t)(GetTickCount64() / 1000); }
static uint32_t    real_time(void*)                              { return (uint32_t)time(0); }
static const char* country(void*)                                { return "US"; }
static uint64_t    voice_none(void*)                             { return 2; }   // k_EVoiceResultNotRecording
static uint64_t    voice_nodata(void*)                           { return 3; }   // k_EVoiceResultNoData (anything but BufferTooSmall)
static bool        stat_zero(void*, const char*, void* p)        { memset(p, 0, 4); return true; }
static bool        get_ach(void*, const char* n, bool* pb)       { *pb = g_ach[n]; return true; }
static bool        get_ach_time(void*, const char* n, bool* pb, uint32_t* t) { *pb = g_ach[n]; *t = 0; return true; }
static bool        set_ach(void*, const char* n) {
    retro_log("achievement unlocked: %s", n);
    g_ach[n] = true;
    UserAchievementStored_t s = {APPID, false, {0}, 0, 0}; strncpy(s.name, n, sizeof s.name - 1);
    post(1103, &s, sizeof s);
    return true;
}
static bool request_stats(void*) { UserStatsReceived_t r = {APPID, 1, g_steamid}; post(1101, &r, sizeof r); return true; }

// The game hex-encodes this ticket into the "token" it POSTs to the auth server. Only handed out when a
// discoveries server is configured; otherwise the game gets no ticket and stays quiet, as before.
static uint32_t g_tickets;
static uint32_t auth_ticket(void*, void* buf, int max, uint32_t* pcb) {
    if (pcb) *pcb = 0;
    if (!g_srv.on || max < 32) return 0;
    struct { char magic[8]; uint64_t steamid, unixtime, zero; } t = {{'N','M','S','R','E','T','R','O'}, g_steamid, (uint64_t)time(0), 0};
    memcpy(buf, &t, 32); *pcb = 32;
    GetAuthSessionTicketResponse_t r = {++g_tickets, 1};
    post(163, &r, sizeof r);
    retro_log("auth ticket %u issued", r.ticket);
    return r.ticket;
}

static void* find_iface(const char* version);
static void* client_get (void*, int32_t, int32_t, const char* version) { return find_iface(version); }
static void* client_get2(void*, int32_t, const char* version)          { return find_iface(version); }   // GetISteamUtils has no user arg

static void* find_iface(const char* v) {
    auto it = g_byname.find(v);
    if (it != g_byname.end()) return OBJ(it->second);
    if (g_nif == 32) return OBJ(&g_if[0]);
    Iface* f = make(_strdup(v)); g_byname[v] = f;
    void** vt = f->vt;
    bool known = true;
    if (!strncmp(v, "SteamClient", 11)) {                 // slot numbers follow the SDK headers for the versions these builds use
        for (int s : {0, 1, 2, 3}) vt[s] = (void*)&ret1;
        for (int s : {5, 6, 8, 10, 11, 12, 13, 14, 15, 16, 17, 18, 23, 24, 25, 26, 27, 28, 29, 30, 34, 35, 36}) vt[s] = (void*)&client_get;
        vt[9] = (void*)&client_get2;
    } else if (!strncmp(v, "SteamUser0", 10)) {          // SteamUser019
        vt[0] = (void*)&ret1; vt[1] = (void*)&ret1; vt[2] = (void*)&my_id;
        vt[9] = (void*)&voice_none; vt[10] = (void*)&voice_none; vt[11] = (void*)&voice_nodata;
        vt[13] = (void*)&auth_ticket;
    } else if (!strncmp(v, "SteamFriends", 12)) {        // SteamFriends015
        vt[0] = (void*)&my_name; vt[2] = (void*)&ret1;
        for (int s : {7, 9, 11, 14, 20, 21, 45, 47}) vt[s] = (void*)&ret_empty;
        for (int s : {4, 19, 25, 39, 41, 51, 57}) vt[s] = (void*)&zero_out<8>;
    } else if (!strncmp(v, "SteamUtils", 10)) {          // SteamUtils008/009
        vt[0] = (void*)&secs_active; vt[1] = (void*)&secs_up; vt[2] = (void*)&ret1; vt[3] = (void*)&real_time;
        vt[4] = (void*)&country; vt[9] = (void*)&appid; vt[12] = (void*)&ret_m1; vt[23] = (void*)&my_lang;
    } else if (!strncmp(v, "STEAMUSERSTATS", 14)) {      // STEAMUSERSTATS_INTERFACE_VERSION011
        vt[0] = (void*)&request_stats; vt[1] = (void*)&stat_zero; vt[2] = (void*)&stat_zero; vt[3] = (void*)&ret1; vt[4] = (void*)&ret1;
        vt[6] = (void*)&get_ach; vt[7] = (void*)&set_ach; vt[8] = (void*)&ret1; vt[9] = (void*)&get_ach_time; vt[10] = (void*)&ret1;
        for (int s : {12, 15, 24}) vt[s] = (void*)&ret_empty;
    } else if (!strncmp(v, "STEAMAPPS", 9)) {            // STEAMAPPS_INTERFACE_VERSION008
        for (int s : {0, 6, 7, 19}) vt[s] = (void*)&ret1;   // subscribed, DLC installed (pre-order ship, like Goldberg's default)
        vt[4] = (void*)&my_lang; vt[5] = (void*)&my_lang; vt[20] = (void*)&my_id; vt[21] = (void*)&ret_empty;
    } else if (!strncmp(v, "SteamController", 15)) {     // SteamController003/005: Init ok, no controllers, zeroed action data
        vt[0] = (void*)&ret1; vt[1] = (void*)&ret1;
        vt[9] = (void*)&zero_out<2>; vt[12] = (void*)&zero_out<16>; vt[21] = (void*)&zero_out<40>;
    } else if (!strncmp(v, "SteamMatchMaking0", 17)) {   // SteamMatchMaking009: lobby calls fail, IDs come back zero
        for (int s : {12, 18, 35}) vt[s] = (void*)&zero_out<8>;
        vt[19] = (void*)&ret_empty; vt[24] = (void*)&ret_empty;
    } else known = false;                                // everything else (UGC, networking, screenshots, ...) answers 0 to every call
    retro_log("interface %s -> %s", v, known ? "emulated" : "generic stub");
    return OBJ(f);
}

// ---- exports: exactly what the NMS.exe builds import ----
#define API extern "C" __declspec(dllexport)
static int g_init;   // bumps on Init/Shutdown; SteamInternal_ContextInit re-runs the game's context init when it changes

API bool     SteamAPI_Init()                                  { g_init++; request_stats(0); retro_log("SteamAPI_Init"); return true; }
API void     SteamAPI_Shutdown()                              { g_init++; retro_log("SteamAPI_Shutdown"); }
API bool     SteamAPI_RestartAppIfNecessary(uint32_t)         { return false; }
API int32_t  SteamAPI_GetHSteamUser()                         { return 1; }
API int32_t  SteamAPI_GetHSteamPipe()                         { return 1; }
API void*    SteamInternal_CreateInterface(const char* v)     { return find_iface(v); }
API void     SteamAPI_RegisterCallResult(CCallbackBase*, uint64_t)   {}   // every SteamAPICall_t we hand out is 0, the game never registers one
API void     SteamAPI_UnregisterCallResult(CCallbackBase*, uint64_t) {}

API void SteamAPI_RegisterCallback(CCallbackBase* cb, int id) {
    cb->id = id; cb->flags |= 1;   // k_ECallbackFlagsRegistered
    g_cbs.push_back(cb);
    retro_log("callback %d registered", id);
}
API void SteamAPI_UnregisterCallback(CCallbackBase* cb) {
    cb->flags &= ~1;
    for (size_t i = 0; i < g_cbs.size(); i++) if (g_cbs[i] == cb) { g_cbs.erase(g_cbs.begin() + i); break; }
}
API void SteamAPI_RunCallbacks() {
    auto q = std::move(g_pending); g_pending.clear();
    for (auto& p : q)
        for (CCallbackBase* cb : std::vector<CCallbackBase*>(g_cbs))
            if (cb->id == p.first) ((void (*)(CCallbackBase*, void*))cb->vt[0])(cb, p.second.data());
}
// ctx = { void (*init)(void* ctx); uintptr_t counter; CSteamAPIContext ctx; } (steam_api_internal.h)
API void* SteamInternal_ContextInit(void** ctx) {
    if ((intptr_t)ctx[1] != g_init) { ctx[1] = (void*)(intptr_t)g_init; ((void (*)(void*))ctx[0])(&ctx[2]); }
    return &ctx[2];
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID) {
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    DisableThreadLibraryCalls(h);
    g_start = GetTickCount64();
    GetModuleFileNameA(h, g_dir, MAX_PATH); *strrchr(g_dir, '\\') = 0;
    char p[MAX_PATH]; snprintf(p, sizeof p, "%s\\steam_api64.retro.log", g_dir);
    if (GetFileAttributesA(p) != INVALID_FILE_ATTRIBUTES) g_log = fopen(p, "a");

    HMODULE exe = GetModuleHandleA(0);
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((uint8_t*)exe + ((IMAGE_DOS_HEADER*)exe)->e_lfanew);
    if (nt->FileHeader.TimeDateStamp > LAST_SUPPORTED_BUILD) {
        retro_log("exe timestamp %08x is newer than 1.38, refusing", nt->FileHeader.TimeDateStamp);
        MessageBoxA(0, "steam_api64.retro only works with No Man's Sky builds up to 1.38 (Atlas Rises).", "steam_api64.retro", MB_ICONERROR);
        TerminateProcess(GetCurrentProcess(), 1);
    }
    load_settings(nt->FileHeader.TimeDateStamp);
    if (g_srv.on) hook_winhttp(exe);   // the import table is not encrypted, so this can happen before the unwrap
    bool wrapped = steamstub_prepare(exe, patch_code);
    if (!wrapped) patch_code();
    retro_log("exe timestamp %08x, %s, steamid %llu savesteamid %llu name %s language %s", nt->FileHeader.TimeDateStamp, wrapped ? "SteamStub found" : "no SteamStub", g_steamid, g_saveid, g_name.c_str(), g_lang.c_str());
    return TRUE;
}
