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

found = {}
for ver in os.listdir(legacy) if os.path.isdir(legacy) else []:
    for name in ("NMS.exe.bak", "NMS.exe"):
        exe = os.path.join(legacy, ver, "Binaries", name)
        if os.path.exists(exe):
            ts = pefile.PE(exe, fast_load=True).FILE_HEADER.TimeDateStamp
            assert ts <= cap, "%s has timestamp %08x, newer than the cap" % (exe, ts)
            found[ver] = defaults.get(ts, 0)
            break
print("exports ok; cap ok; default ids:", found or "no local builds found")
