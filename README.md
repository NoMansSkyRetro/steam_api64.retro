# steam_api64.retro

A drop-in `steam_api64.dll` for the four legacy Steam builds of No Man's Sky
(1.09.1, 1.13, 1.24 and 1.38) that lets them run without the Steam client.
It replaces the Steamless plus Goldberg emulator combination the
[NMS Retro installer](https://github.com/NoMansSkyRetro/Installer) used to apply.

It does two jobs:

1. **Unwraps the SteamStub DRM in memory.** 1.24 and 1.38 ship with the Steam
   DRM wrapper, which leaves the game's code encrypted on disk. The wrapper's own
   loader talks to `steamclient64.dll` directly, so it cannot be satisfied from
   `steam_api64.dll`. Instead, at load time the DLL decrypts the code section with
   the key that sits in the stub header (the same maths Steamless does on disk)
   and redirects the entry point to the game's original one. `NMS.exe` stays
   untouched.
2. **Answers the Steamworks calls these builds make.** Steam ID, persona name,
   language, app ownership, achievements (kept for the session), a working
   callback queue for `SteamInternal_ContextInit` style clients, and harmless
   zero answers for everything else (Workshop, lobbies, voice, Steam Controller).

## Only the four legacy builds

The DLL checks the PE timestamp of the executable that loads it and refuses
anything else with a message box. Steamless works on any SteamStub game and
Goldberg emulates all of Steam; this DLL deliberately does neither. The
whitelist is the `KNOWN_BUILDS` table in `src/steam_api64.cpp`.

| Build  | NMS.exe timestamp | DRM wrapper |
|--------|-------------------|-------------|
| 1.09.1 | `0x57ff70ca`      | none        |
| 1.13   | `0x584983de`      | none        |
| 1.24   | `0x58d42a08`      | SteamStub 3.1 |
| 1.38   | `0x59ce2f3c`      | SteamStub 3.1 |

Both the original (wrapped) `NMS.exe` and a Steamless-unpacked one work.

## Install

Copy `steam_api64.dll` over the one in the game's `Binaries` folder. Settings
are read from the same `steam_settings` folder the installer already writes:

| File | Default | Use |
|------|---------|-----|
| `steam_settings\force_steamid.txt` | `76561197960287930` | Steam ID, which names the `st_<id>` save folder |
| `steam_settings\force_account_name.txt` | `Player` | Persona name |
| `steam_settings\force_language.txt` | `english` | Game language reported by Steam |

To get a log, create an empty `steam_api64.retro.log` next to the DLL. The log
lists every interface the game asks for and the first call to any slot the DLL
does not implement.

## Build

Run `build.bat` with Visual Studio 2019 or newer installed (it finds the
toolset through vswhere). Output is `build\steam_api64.dll`. The only
dependencies are user32 and bcrypt, both part of Windows.

`python tests\check.py` verifies the exports and that the whitelist matches
the executables under `E:\NMSLegacy`.

## How the pieces were found

`src/steamstub.cpp` follows the Steamless 3.1 x64 unpacker: XOR-chained header
before the entry point, AES-256-CBC code section with the IV itself AES-encrypted,
first 16 bytes of ciphertext stolen into the header. The Steamworks interface
versions and the vtable slots each build actually calls were taken from the
Ghidra decompilations of the four executables, which is why the emulation is
small.

## License

MIT, see LICENSE.
