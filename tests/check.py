"""Sanity check for a built steam_api64.dll: exports cover every import the legacy
NMS builds make, and the build cap and default-ID table match the real executables.

    python tests/check.py [path\\to\\steam_api64.dll] [E:\\NMSLegacy]
"""
import os, re, sys
import pefile

HERE = os.path.dirname(os.path.abspath(__file__))
dll = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "build", "steam_api64.dll")
legacy = sys.argv[2] if len(sys.argv) > 2 else r"E:\NMSLegacy"

NEEDED = {"SteamAPI_Init", "SteamAPI_Shutdown", "SteamAPI_RunCallbacks", "SteamAPI_RestartAppIfNecessary",
          "SteamAPI_RegisterCallback", "SteamAPI_UnregisterCallback", "SteamAPI_RegisterCallResult",
          "SteamAPI_UnregisterCallResult", "SteamInternal_CreateInterface", "SteamInternal_ContextInit",
          "SteamAPI_GetHSteamUser", "SteamAPI_GetHSteamPipe"}

pe = pefile.PE(dll)
exports = {e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}
assert NEEDED <= exports, "missing exports: %s" % sorted(NEEDED - exports)

src = open(os.path.join(HERE, "..", "src", "steam_api64.cpp")).read()
cap = int(re.search(r"LAST_SUPPORTED_BUILD = 0x([0-9a-f]{8})", src).group(1), 16)
defaults = {int(t, 16): int(i) for t, i in re.findall(r"\{0x([0-9a-f]{8}), (\d+)\}", src)}
assert max(defaults) == cap, "cap should be the newest build in DEFAULT_IDS"

found, exes = {}, {}
for ver in os.listdir(legacy) if os.path.isdir(legacy) else []:
    for name in ("NMS.exe.bak", "NMS.exe"):
        exe = os.path.join(legacy, ver, "Binaries", name)
        if os.path.exists(exe):
            ts = pefile.PE(exe, fast_load=True).FILE_HEADER.TimeDateStamp
            assert ts <= cap, "%s has timestamp %08x, newer than the cap" % (exe, ts)
            found[ver] = defaults.get(ts, 0)
            exes[ver] = exe
            break


# patch_save_id's signature: call [rax+0x10] (GetSteamID), mov rax,[rsp+disp8], then within a few
# bytes "mov byte [reg+8],1". Only the save/cache manager writes that flag, so the hit count is
# fixed per build: one where the two managers share a constructor, two where it is inlined into both.
SAVE_ID_SITES = {0x57ff70ca: 1, 0x584983de: 1, 0x58d42a08: 2, 0x59ce2f3c: 2}

def save_id_sites(exe):
    pe = pefile.PE(exe)
    n = 0
    for sec in pe.sections:
        if not sec.Characteristics & 0x20000000:   # IMAGE_SCN_MEM_EXECUTE
            continue
        t = sec.get_data()
        for m in re.finditer(re.escape(bytes.fromhex('FF 50 10 48 8B 44 24')), t):
            i = m.start()
            n += any(t[i+j] == 0xC6 and (t[i+j+1] & 0xF8) == 0x40 and (t[i+j+1] & 7) != 4
                     and t[i+j+2] == 0x08 and t[i+j+3] == 0x01 for j in range(8, 18))
    return n

def wrapped(pe):
    """True when SteamStub still holds the code section, which leaves nothing to match."""
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    h = bytearray(pe.get_data(ep - 0xF0, 0xF0))
    key = int.from_bytes(h[:4], "little")
    for i in range(4, 0xF0, 4):
        v = int.from_bytes(h[i:i+4], "little")
        h[i:i+4] = (v ^ key).to_bytes(4, "little")
        key = v
    return int.from_bytes(h[4:8], "little") == 0xC0DEC0DF

checked = 0
for ver, exe in exes.items():
    for name in (exe, exe.removesuffix(".bak")):   # .bak may be the original, still wrapped
        if not os.path.exists(name):
            continue
        pe = pefile.PE(name)
        want = SAVE_ID_SITES.get(pe.FILE_HEADER.TimeDateStamp)
        if want is None or wrapped(pe):
            continue
        got = save_id_sites(name)
        assert got == want, "%s: save id signature matched %d sites, expected %d" % (name, got, want)
        checked += 1
        break

print("exports ok; cap ok; save id signature ok on %d build(s); default ids:" % checked, found or "no local builds found")
