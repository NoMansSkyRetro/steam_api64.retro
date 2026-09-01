"""Sanity check for a built steam_api64.dll: exports cover every import the four
NMS builds make, and the build whitelist in the DLL matches the real executables.

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
whitelist = {int(m, 16): v for m, v in re.findall(r"\{0x([0-9a-f]{8}), \"([\d.]+)\"\}", src)}
assert len(whitelist) == 4, whitelist

found = {}
for ver in os.listdir(legacy) if os.path.isdir(legacy) else []:
    for name in ("NMS.exe.bak", "NMS.exe"):
        exe = os.path.join(legacy, ver, "Binaries", name)
        if os.path.exists(exe):
            ts = pefile.PE(exe, fast_load=True).FILE_HEADER.TimeDateStamp
            assert ts in whitelist, "%s has timestamp %08x, not in whitelist" % (exe, ts)
            found[whitelist[ts]] = exe
            break
print("exports ok; whitelist matches", ", ".join(sorted(found)) or "no local builds found")
