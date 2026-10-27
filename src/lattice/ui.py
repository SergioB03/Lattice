"""Local web UI: explore entities, work the review queue, watch the ledger.

Standard library only. Binds to 127.0.0.1 by default. POST requests need the
custom ``X-Lattice`` header and a localhost ``Host``/``Origin`` (blocks CSRF and
DNS rebinding), and approving or rejecting still needs the owner passphrase.
"""

from __future__ import annotations

import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import ledger
from .core import AuthError, Lattice, LatticeError

_LOCK = threading.Lock()


def _entity_payload(lat: Lattice, ref: str) -> dict[str, Any]:
    ent, cands = lat.resolve_or_candidates(ref)
    if ent is None:
        return {"candidates": cands}
    eid = ent["id"]
    row = lat.conn.execute("SELECT type, name, summary, created_by, created_seq FROM entities WHERE id=?", (eid,)).fetchone()
    aliases = [r[0] for r in lat.conn.execute("SELECT alias FROM aliases WHERE entity_id=? ORDER BY alias", (eid,))]
    names = {}

    def name(i: str) -> str:
        if i not in names:
            r = lat.conn.execute("SELECT name, type FROM entities WHERE id=?", (i,)).fetchone()
            names[i] = {"name": r[0], "type": r[1]} if r else {"name": i, "type": "?"}
        return names[i]

    def shape(f: dict[str, Any], direction: str) -> dict[str, Any]:
        other = f["object"] if direction == "out" else f["subject"]
        return f | {"direction": direction, "other": other, "other_name": name(other)["name"] if other else "",
                    "other_type": name(other)["type"] if other else ""}

    hist = lat.history(eid, limit=200)
    pending = [p for p in lat.list_proposals("pending", limit=100) if any(i["target"] == eid for i in p["plan"])]
    return {
        "id": eid, "type": row[0], "name": row[1], "summary": row[2], "created_by": row[3], "created_seq": row[4],
        "aliases": aliases,
        "facts": [shape(f, "out") for f in lat.facts(eid)] + [shape(f, "in") for f in lat.facts(eid, direction="in")],
        "history": [shape(f, "out" if f["subject"] == eid else "in") for f in hist if f["status"] != "current"],
        "pending": pending,
        "context": lat.context(eid, budget_tokens=700),
    }


class Handler(BaseHTTPRequestHandler):
    lat: Lattice
    port: int

    def log_message(self, *a):  # quiet
        return

    def _send(self, code: int, body: Any, ctype: str = "application/json") -> None:
        data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:")
        self.end_headers()
        self.wfile.write(data)

    def _host_ok(self) -> bool:
        host = urlparse("//" + (self.headers.get("Host") or "")).hostname or ""
        return host in ("127.0.0.1", "localhost", "::1")

    def do_GET(self) -> None:
        if not self._host_ok():
            return self._send(403, {"error": "bad host"})
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        try:
            with _LOCK:
                if u.path in ("/", "/index.html"):
                    html = resources.files("lattice").joinpath("ui/index.html").read_bytes()
                    return self._send(200, html, "text/html")
                if u.path == "/api/stats":
                    return self._send(200, self.lat.stats() | {"owner": self.lat.owner,
                                                               "locked": self.lat.human_writes_locked})
                if u.path == "/api/search":
                    return self._send(200, self.lat.search(q.get("q", ""), limit=int(q.get("limit", 12))))
                if u.path == "/api/entity":
                    return self._send(200, _entity_payload(self.lat, q.get("id", "")))
                if u.path == "/api/proposals":
                    return self._send(200, self.lat.list_proposals(q.get("status", "pending"), limit=int(q.get("limit", 50))))
                if u.path == "/api/ledger":
                    head = self.lat.head()[0]
                    n = int(q.get("limit", 40))
                    evs = [{"seq": e.seq, "ts": e.ts, "type": e.type, "actor": e.actor, "hash": e.hash, "prev": e.prev_hash}
                           for e in ledger.iter_events(self.lat.conn, after_seq=max(0, head - n))]
                    return self._send(200, list(reversed(evs)))
                if u.path == "/api/verify":
                    return self._send(200, self.lat.verify())
                if u.path == "/api/recent":
                    rows = self.lat.conn.execute("SELECT id, type, name FROM entities ORDER BY created_seq DESC, id LIMIT 12").fetchall()
                    return self._send(200, [{"id": r[0], "type": r[1], "name": r[2]} for r in rows])
        except (LatticeError, ValueError) as exc:
            return self._send(400, {"error": str(exc)})
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        origin = self.headers.get("Origin", "")
        if not self._host_ok() or self.headers.get("X-Lattice") != "1" or (
                origin and urlparse(origin).hostname not in ("127.0.0.1", "localhost")):
            return self._send(403, {"error": "cross-site request refused"})
        u = urlparse(self.path)
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if not 0 <= n <= 1_000_000:
                return self._send(413, {"error": "bad length"})
            body = json.loads(self.rfile.read(n) or b"{}")
            with _LOCK:
                parts = u.path.strip("/").split("/")
                if len(parts) == 4 and parts[:2] == ["api", "proposals"] and parts[3] in ("approve", "reject"):
                    who = self.lat.owner  # only the owner holds the passphrase
                    if not isinstance(body, dict) or not isinstance(body.get("passphrase", ""), str):
                        return self._send(400, {"error": "body must be an object with a string passphrase"})
                    if parts[3] == "approve":
                        return self._send(200, self.lat.approve(parts[2], who, body.get("passphrase", ""),
                                                                seen_decision=str(body.get("decision", ""))))
                    return self._send(200, self.lat.reject(parts[2], who, body.get("passphrase", ""), body.get("reason", "")))
                if u.path == "/api/propose":
                    return self._send(200, self.lat.propose(self.lat.owner, body["ops"], body.get("justification", ""),
                                                            passphrase=body.get("passphrase")))
        except AuthError as exc:
            return self._send(401, {"error": str(exc)})
        except (LatticeError, ValueError, KeyError, TypeError, AttributeError, RecursionError) as exc:
            return self._send(400, {"error": str(exc)[:300]})
        self._send(404, {"error": "not found"})


def make_server(lat: Lattice, host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    handler = type("LatticeHandler", (Handler,), {"lat": lat, "port": port})
    return ThreadingHTTPServer((host, port), handler)


def serve(lat: Lattice, host: str = "127.0.0.1", port: int = 8765, open_browser: bool = False) -> None:
    import os
    if host not in ("127.0.0.1", "localhost", "::1") and os.environ.get("LATTICE_UI_ALLOW_REMOTE") != "1":
        raise LatticeError("the UI only binds to localhost (set LATTICE_UI_ALLOW_REMOTE=1 if you really mean it)")
    srv = make_server(lat, host, port)
    url = f"http://{'127.0.0.1' if host in ('0.0.0.0', '') else host}:{port}/"
    print(f"Lattice UI on {url}  (Ctrl+C to stop)")
    if open_browser:
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
