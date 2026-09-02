# steam_api64.retro

A drop-in `steam_api64.dll` for the legacy Steam builds of No Man's Sky (up to
1.38, Atlas Rises) that lets them run without the Steam client. It replaces the
Steamless plus Goldberg emulator combination the
[NMS Retro installer](https://github.com/NoMansSkyRetro/Installer) used to apply.

It does two jobs:

1. **Unwraps the SteamStub DRM in memory.** Builds from Path Finder (1.2x)
   onwards ship with the Steam DRM wrapper, which leaves the game's code
   encrypted on disk. The wrapper's own loader talks to `steamclient64.dll`
   directly, so it cannot be satisfied from `steam_api64.dll`. Instead, at load
   time the DLL decrypts the code section with the key that sits in the stub
   header and redirects the entry point to the game's original one. `NMS.exe`
   stays untouched on disk.
2. **Answers the Steamworks calls these builds make.** Steam ID, persona name,
   language, app ownership, achievements (kept for the session), a working
   callback queue for `SteamInternal_ContextInit` style clients, and harmless
   zero answers for everything else (Workshop, lobbies, voice, Steam Controller).

## Capped at 1.38

The DLL refuses, with a message box, any executable whose PE timestamp is newer
than the 1.38 build (`LAST_SUPPORTED_BUILD` in `src/steam_api64.cpp`). Every
older build passes. Both the original (wrapped) `NMS.exe` and a
Steamless-unpacked one work.

## Install

Copy `steam_api64.dll` over the one in the game's `Binaries` folder. On first
run the DLL writes `steam_api64.txt` next to itself with the identity it hands
the game; edit it as you like:

```
steamid=138
name=Player
language=english
```

| Key | Meaning |
|-----|---------|
| `steamid` | Any number. The game only uses it to name the save folder, `%APPDATA%\HelloGames\NMS\st_<steamid>`. |
| `name` | Persona name reported by Steam. |
| `language` | Game language reported by Steam. |

The default `steamid` is the version number for the four builds the installer
ships (109, 113, 124, 138) so each build keeps its own saves, and 0 for any
other build. To keep saves made with the old Goldberg setup, set `steamid` to
the 17-digit ID that folder is named after.

To get a log, create an empty `steam_api64.retro.log` next to the DLL. The log
lists every interface the game asks for and the first call to any slot the DLL
does not implement.

## Build

Run `build.bat` with Visual Studio 2019 or newer installed (it finds the
toolset through vswhere). Output is `build\steam_api64.dll`. The only
dependencies are user32 and bcrypt, both part of Windows.

`python tests\check.py` verifies the exports, the cap, and the default IDs
against the executables under `E:\NMSLegacy`.

## Credits

No code from either project is included, but neither part of this DLL would
exist without them:

- [Steamless](https://github.com/atom0s/Steamless) by atom0s. The SteamStub
  3.1 header layout, the XOR chain, and the AES-256-CBC decryption with its
  self-encrypted IV in `src/steamstub.cpp` follow the Steamless x64 unpacker.
- [Goldberg Steam Emulator](https://gitlab.com/Mr_Goldberg/goldberg_emulator)
  by Mr_Goldberg. Its collection of Steamworks SDK headers, one per interface
  version, is where the vtable slot numbers in `src/steam_api64.cpp` come from.
- Valve's Steamworks SDK, which those headers originate from.

## License

MIT, see LICENSE.
