// steam_api64.retro: stand-in steam_api64.dll for the legacy No Man's Sky builds
// (1.09.1 through 1.38 on Steam). Unwraps the SteamStub DRM in memory (see
// steamstub.cpp) and answers the handful of Steamworks calls these builds make.
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <string>
#include <map>
#include <vector>
#include <utility>

bool steamstub_prepare(HMODULE exe);   // steamstub.cpp

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

// ---- identity: steam_api64.txt next to the DLL, written with defaults on first run ----
// The Steam ID only has to be a number; the game uses it for the st_<id> save folder name.
static uint64_t    g_steamid;
static std::string g_name = "Player", g_lang = "english";
static ULONGLONG   g_start;
static std::map<std::string, bool> g_ach;   // ponytail: achievements live for the session only, add a file if anyone misses them

static const struct { uint32_t timestamp; uint64_t steamid; } DEFAULT_IDS[] = {   // NMS.exe PE timestamp -> version number, so each build gets its own save folder
    {0x57ff70ca, 109}, {0x584983de, 113}, {0x58d42a08, 124}, {0x59ce2f3c, 138},
};

static void load_settings(uint32_t exe_timestamp) {
    for (auto& d : DEFAULT_IDS) if (d.timestamp == exe_timestamp) g_steamid = d.steamid;
    char p[MAX_PATH]; snprintf(p, sizeof p, "%s\\steam_api64.txt", g_dir);
    FILE* f = fopen(p, "r");
    if (!f) {
        if ((f = fopen(p, "w")) != 0) { fprintf(f, "steamid=%llu\nname=%s\nlanguage=%s\n", g_steamid, g_name.c_str(), g_lang.c_str()); fclose(f); }
        return;
    }
    char line[256];
    while (fgets(line, sizeof line, f)) {
        char* v = strchr(line, '=');
        if (!v || line[0] == '#') continue;
        *v++ = 0;
        size_t n = strlen(v);
        while (n && (v[n - 1] == '\n' || v[n - 1] == '\r' || v[n - 1] == ' ')) v[--n] = 0;
        if (!n) continue;
        if (!strcmp(line, "steamid")) g_steamid = strtoull(v, 0, 10);
        else if (!strcmp(line, "name")) g_name = v;
        else if (!strcmp(line, "language")) g_lang = v;
    }
    fclose(f);
}

// ---- callbacks ----
struct CCallbackBase { void** vt; uint8_t flags; int id; };   // vt[0] = Run(void* param)
static std::vector<CCallbackBase*> g_cbs;
static std::vector<std::pair<int, std::vector<uint8_t>>> g_pending;
static void post(int id, const void* data, size_t n) { g_pending.emplace_back(id, std::vector<uint8_t>((const uint8_t*)data, (const uint8_t*)data + n)); }

#pragma pack(push, 8)
struct UserStatsReceived_t     { uint64_t gameId; int result; uint64_t steamId; };                                  // 1101
struct UserAchievementStored_t { uint64_t gameId; bool group; char name[128]; uint32_t cur, max; };                 // 1103
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
static uint32_t    no_ticket(void*, void*, int, uint32_t* pcb)   { if (pcb) *pcb = 0; return 0; }
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
        vt[13] = (void*)&no_ticket;
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

// ---- exports: exactly what the four NMS.exe builds import ----
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
    bool wrapped = steamstub_prepare(exe);
    retro_log("exe timestamp %08x, %s, steamid %llu name %s language %s", nt->FileHeader.TimeDateStamp, wrapped ? "SteamStub found" : "no SteamStub", g_steamid, g_name.c_str(), g_lang.c_str());
    return TRUE;
}
