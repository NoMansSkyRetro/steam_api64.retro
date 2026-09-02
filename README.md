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

Two optional extras, both off by default: skipping the mods-enabled warning
screen, and sending the game's discoveries traffic to a server of your choice.

## Capped at 1.38

The DLL refuses, with a message box, any executable whose PE timestamp is newer
than the 1.38 build (`LAST_SUPPORTED_BUILD` in `src/steam_api64.cpp`). Every
older build passes. Both the original (wrapped) `NMS.exe` and a
Steamless-unpacked one work.

## Install and settings

Copy `steam_api64.dll` over the one in the game's `Binaries` folder. On first
run the DLL writes `steam_api64.txt` next to itself; edit it as you like:

```
steamid=138
name=Player
language=english
disablemodwarning=false
discoveriesserver=
```

| Key | Meaning |
|-----|---------|
| `steamid` | Any number. The game only uses it to name the save folder, `%APPDATA%\HelloGames\NMS\st_<steamid>`. |
| `name` | Persona name reported by Steam. Also sent as `user` to the discoveries server. |
| `language` | Game language reported by Steam. |
| `disablemodwarning` | `true` skips the "mods enabled" screen shown at boot once `PCBANKS\DISABLEMODS.TXT` is removed. 1.13 and later; 1.09.1 has no mod system. |
| `discoveriesserver` | `http://host:port` or `https://host[:port]`. Empty keeps the game pointed at Hello Games (whose 1.x servers are gone). |

The default `steamid` is the version number for the four builds the installer
ships (109, 113, 124, 138) so each build keeps its own saves, and 0 for any
other build. To keep saves made with the old Goldberg setup, set `steamid` to
the 17-digit ID that folder is named after.

To get a log, create an empty `steam_api64.retro.log` next to the DLL. The log
lists every interface the game asks for, the first call to any slot the DLL
does not implement, and everything the two extras do.

### Mod warning

The pak loader sets a "mods loaded" flag after mounting `PCBANKS\MODS`, and the
boot screens show the warning only when it is set. With `disablemodwarning=true`
the DLL finds the instruction that stores the flag (one unique byte pattern in
1.13, 1.24 and 1.38) and makes it store 0 instead. Mods still load; nothing else
reads the flag. If the pattern is not found exactly once the DLL leaves the game
alone and says so in the log.

### Discoveries server

These builds authenticate against `pc-nms-auth.nomanssky.com` with a Steam auth
ticket and take every other endpoint from the `routes` in that reply, so
redirecting the auth connection is enough to move the whole discoveries flow.
With `discoveriesserver` set the DLL:

- hooks the game's `WinHttpConnect`, `WinHttpOpenRequest` and
  `WinHttpCloseHandle` imports and sends any connection to a `nomanssky.com` or
  `hellogames` host to your server instead, using the scheme and port from the
  setting (plain HTTP works; HTTPS skips certificate validation);
- hands the game an auth ticket, which it would otherwise not get without Steam.

What your server receives first is `POST /Steam` (the path is the platform
name) with headers `X-Hg-Key: a7427078-971b-4e85-911f-1c912a4f8832`,
`X-Hg-CorrelationId: <guid>`, `User-Agent: Mozilla/5.0 (Skyscraper; Win|Final )`
and a JSON body:

```json
{"token":"4E4D53524554524F...","version":"275850s3000","user":"Traveller","branch":"local","buildnum":0}
```

`token` is the hex of the 32-byte ticket the DLL issues: the ASCII magic
`NMSRETRO`, the `steamid` as a little-endian 64-bit integer, the issue time as a
little-endian 64-bit Unix timestamp, and 8 zero bytes. The game expects a JSON
reply shaped like this (route URLs may use `http://`, an IP, and a port):

```json
{
  "jwt": "opaque session token",
  "ts": 1700000000,
  "routes": {
    "queryexact": "http://host:port/queryexact",
    "querycategory": "...", "queryall": "...", "queryvoxel": "...", "querybase": "...",
    "submitdiscovery": "...", "submitmessage": "...", "submitbase": "...",
    "reportcontent": "...", "reportbase": "...", "blobserve": "..."
  },
  "settings": {"discoveryrefreshrate": 30, "messages": false}
}
```

`ts` must be positive. A 403 from the auth call is treated by the game as a ban.
The individual route payloads (`GcAtlasSendSubmitDiscoveryExact` and friends) are
the game's own serialized structures and are not documented here.

## Build

Run `build.bat` with Visual Studio 2019 or newer installed (it finds the
toolset through vswhere). Output is `build\steam_api64.dll`. The only
dependencies are user32, bcrypt and winhttp, all part of Windows.

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
