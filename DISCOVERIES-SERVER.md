# Running your own discoveries server

The legacy No Man's Sky builds (1.09.1 to 1.38) upload discoveries, bases and
messages to Hello Games' "Azure" service and pull other players' discoveries
back from it. Those servers are long gone. With `discoveriesserver=` set in
`steam_api64.txt`, steam_api64.retro points the game at a server of your choice
instead. This document describes what that server sees and what it has to say
back, and ships a dummy server you can start from.

Everything here was taken from the 1.24 executable and confirmed live against
the dummy server with 1.24; the same strings and code exist in 1.09.1, 1.13 and
1.38.

## How the game talks to a server

1. **Auth.** At boot the game asks Steam for an auth session ticket, then POSTs
   it to `https://pc-nms-auth.nomanssky.com/Steam`. (`pc` is the "prod"
   environment name; the path is the platform name.)
2. **Routes.** The reply carries a session token, a timestamp, a `routes` object
   with one URL per endpoint, and a couple of settings. From then on the game
   uses those URLs, whatever host, scheme or port they name. Hello Games' server
   is never contacted again.
3. **Play.** Discovery uploads and queries go to the route URLs as the player
   scans, names things, builds, and warps.

The DLL sits in front of step 1 only:

- Without the Steam client the game would get no ticket and never attempt the
  auth call. The DLL issues a synthetic ticket (format below).
- The game's `WinHttpConnect` is hooked. Any connection to a `nomanssky.com` or
  `hellogames` host is opened to the configured server instead, with the scheme
  and port from the setting. Plain `http://` is fine; `https://` works too and
  skips certificate validation so a self-signed certificate is enough.

Because the routes come from your own reply, steps 2 and 3 need no help from
the DLL. Point the routes at the same server, or at any other.

## The auth request

```
POST /Steam HTTP/1.1
Host: your.server:port
Content-Type: application/json
User-Agent: Mozilla/5.0 (Skyscraper; Win|Final )
X-Hg-Key: a7427078-971b-4e85-911f-1c912a4f8832
X-Hg-CorrelationId: cd2cfee6-1673-4323-89b5-c499c260d783
Connection: Keep-Alive

{"token":"4E4D53524554524F7C000000000000009272976A000000000000000000000000",
 "version":"275850s3000","user":"Traveller","branch":"local","buildnum":0}
```

| Field | Meaning |
|-------|---------|
| `token` | Hex of the 32-byte auth ticket (see below). |
| `version` | App id plus platform letter and protocol number: `275850s3000` on 1.24, `275850s4000` on 1.38. 1.09.1 and 1.13 have no protocol suffix in their strings, so expect a shorter value there. Use it to tell builds apart. |
| `user` | The `name` from `steam_api64.txt`. |
| `branch`, `buildnum` | Steam beta branch and build number; `local` and `0` under the DLL. |
| `X-Hg-Key` | Constant API key baked into the game. |
| `X-Hg-CorrelationId` | A new GUID per request. Also sent on every route call. |

### The ticket

A real Steam ticket is opaque binary that only Valve can verify. The DLL's
replacement is 32 bytes the server can read directly:

| Offset | Size | Content |
|-------:|-----:|---------|
| 0 | 8 | ASCII `NMSRETRO` |
| 8 | 8 | `steamid` from `steam_api64.txt`, little-endian unsigned 64-bit |
| 16 | 8 | Issue time, little-endian Unix timestamp |
| 24 | 8 | Zero |

The token in the example decodes to steamid 124, issued at 1788310162. Nothing
about it is secret: anyone can forge one, so treat `steamid` and `user` as a
display identity, not as proof of anything.

## The auth reply

HTTP 200 with a JSON body:

```json
{
  "jwt": "opaque session string, up to 511 characters",
  "ts": 1788310162,
  "routes": {
    "queryexact":      "http://your.server:port/queryexact",
    "querycategory":   "http://your.server:port/querycategory",
    "queryall":        "http://your.server:port/queryall",
    "queryvoxel":      "http://your.server:port/queryvoxel",
    "querybase":       "http://your.server:port/querybase",
    "submitdiscovery": "http://your.server:port/submitdiscovery",
    "submitmessage":   "http://your.server:port/submitmessage",
    "submitbase":      "http://your.server:port/submitbase",
    "reportcontent":   "http://your.server:port/reportcontent",
    "reportbase":      "http://your.server:port/reportbase",
    "blobserve":       "http://your.server:port/blobserve"
  },
  "settings": {
    "discoveryrefreshrate": 30,
    "messages": false
  }
}
```

Rules the game's parser enforces:

- `jwt` must be a string and `ts` a number greater than zero, or the reply is
  rejected and the game retries with a growing back-off.
- Every route is parsed as `scheme://host[:port]/path`. `http` and `https` are
  accepted, the host may be a name or an IPv4 address, the port is optional
  (80 or 443 by default). A route that fails to parse is skipped, not fatal.
- `discoveryrefreshrate` is a number of seconds; `messages` is a boolean that
  turns the in-game message feature on.
- A **403** on the auth call makes the game consider the player banned for the
  session. Use it deliberately or not at all.

The route table grew with the game. Each build reads only the names it knows and
ignores the rest, so a server can always send the full 1.38 set:

| Build | Routes |
|-------|--------|
| 1.09.1 | `queryexact`, `querycategory`, `queryall`, `queryvoxel`, `submitdiscovery`, `reportcontent`, `blobserve` (no `messages` setting either) |
| 1.13 | the above plus `submitmessage` |
| 1.24 | the eleven shown above |
| 1.38 | the eleven plus `querymonument` and `submitmonument` |

The game keeps `jwt` but, at least in 1.24, was not observed sending it back on
route calls. Do not build authentication on it; the `X-Hg-CorrelationId` is a
fresh GUID each time and the route payloads carry the player's own name and ID
fields.

## Route calls

Each route is a POST with the same `X-Hg-Key` and `X-Hg-CorrelationId` headers
and one of two content types:

- `application/json` for everything but screenshots. The body is the game's own
  serialization of the matching `GcAtlasSend...` structure (for example
  `GcAtlasSendSubmitDiscoveryExact` for `submitdiscovery`). Field names follow
  those structures, which libMBIN documents for each version.
- `multipart/form-data;boundary=hellogamesmultipart` when a screenshot rides
  along: a `jsondata` part with the JSON and a `binarydata` part with
  `screenshot.tga`.

Replies are JSON that the game parses into the matching `GcAtlasReceive...`
structure. The dummy server answers `{}` to all of them, which the game accepts
as "nothing here". Capturing real payloads is the point of the dummy server:
every body it receives is written to its log, so the exact shape of each request
can be read off a session of play rather than reconstructed.

## The dummy server

`tools/dummy_discoveries_server.py` is a dependency-free Python script:

```
python tools\dummy_discoveries_server.py 8085 discoveries.log
```

Then, in the game's `steam_api64.txt`:

```
discoveriesserver=http://127.0.0.1:8085
```

It answers any POST to `/Steam` (or `/Galaxy`, `/PSN`, `/user`) with the reply
above, routes pointing back at itself, decodes the ticket into the log, and
returns `{}` to everything else. Create an empty `steam_api64.retro.log` next to
the DLL as well and you get both sides: the DLL logs the redirect and each
request it opens, the server logs what arrived.

## What a real server would add

The dummy server is a mirror. A working community server needs, roughly in this
order:

1. **Identity.** Decode the ticket, keep `steamid` and `user`, hand back a `jwt`
   you generate. Since the ticket is forgeable, moderation has to work on
   behaviour, not on trust in the ID.
2. **Storage keyed the way the game asks.** `queryexact` and `queryvoxel` look
   up by the game's universe addresses; `querycategory` and `queryall` page
   through discoveries by category; `querybase` fetches bases. Log a real
   session with the dummy server to see the exact keys each query sends and the
   fields the game expects back, then design the tables around them.
3. **Submissions.** `submitdiscovery`, `submitbase`, `submitmessage` store the
   posted structure; `blobserve` stores and serves the screenshot bytes from the
   multipart uploads; `reportcontent` and `reportbase` are the in-game report
   buttons.
4. **Versioning.** Structures changed between 1.09.1, 1.13, 1.24 and 1.38.
   Branch on the `version` string from the auth call, or run one server per
   build.
5. **Rate and size limits.** The game polls `queryall` on the
   `discoveryrefreshrate` you set, so that number is your load knob.

Everything else (HTTPS with a real certificate, accounts, web front-end) is
ordinary web work the game does not care about.
