"""Dummy No Man's Sky discoveries server for steam_api64.retro.

Answers the game's auth call with routes that point back at itself, replies
to everything else with an empty JSON object, and logs every request (method,
path, headers, body) so you can see exactly what the game sends.

    python dummy_discoveries_server.py [port] [logfile]

Then set  discoveriesserver=http://127.0.0.1:<port>  in the game's steam_api64.txt.
See DISCOVERIES-SERVER.md for the protocol.
"""
import json, sys, time
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8085
LOG = sys.argv[2] if len(sys.argv) > 2 else "discoveries.log"
ROUTES = ["queryexact", "querycategory", "queryall", "queryvoxel", "querybase", "submitdiscovery",
          "submitmessage", "submitbase", "reportcontent", "reportbase", "blobserve"]


def parse_token(hex_token):
    """The DLL's ticket: 'NMSRETRO' + steamid (u64 LE) + unix time (u64 LE) + 8 zero bytes."""
    raw = bytes.fromhex(hex_token)
    if len(raw) != 32 or raw[:8] != b"NMSRETRO":
        return None
    return {"steamid": int.from_bytes(raw[8:16], "little"), "issued": int.from_bytes(raw[16:24], "little")}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def _log(self, body):
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%H:%M:%S')} {self.command} {self.path}\n")
            for k, v in self.headers.items():
                f.write(f"   {k}: {v}\n")
            if body:
                f.write(f"   body: {body[:4000]!r}\n")

    def _reply(self, obj, status=200):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._log(b"")
        self._reply({})

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self._log(body)
        if self.path.rstrip("/").endswith(("/Steam", "/Galaxy", "/PSN", "/user")):   # the auth call
            try:
                who = parse_token(json.loads(body)["token"])
            except (ValueError, KeyError):
                who = None
            with open(LOG, "a", encoding="utf-8") as f:
                f.write(f"   auth from {who}\n")
            base = f"http://127.0.0.1:{PORT}"
            return self._reply({
                "jwt": "dummy-session",
                "ts": int(time.time()),
                "routes": {r: f"{base}/{r}" for r in ROUTES},
                "settings": {"discoveryrefreshrate": 30, "messages": False},
            })
        self._reply({})


if __name__ == "__main__":
    print(f"dummy discoveries server on http://127.0.0.1:{PORT}, logging to {LOG}")
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
