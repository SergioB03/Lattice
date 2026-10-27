import http.client
import json
import threading

import pytest

from lattice.core import Lattice
from lattice.demo import seed
from lattice.ui import make_server

PW = "correct horse battery"


@pytest.fixture()
def server(tmp_path):
    lat = Lattice.open(tmp_path / "ui.db")
    lat.init(owner="human:sergio", passphrase=PW)
    seed(lat, "human:sergio", PW)
    srv = make_server(lat, "127.0.0.1", 0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield lat, srv.server_address[1]
    srv.shutdown()


def call(port, method, path, body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = {"Host": f"127.0.0.1:{port}"} | (headers or {})
    data = json.dumps(body).encode() if body is not None else None
    if data is not None:
        h["Content-Type"] = "application/json"
    c.request(method, path, body=data, headers=h)
    r = c.getresponse()
    return r.status, json.loads(r.read() or b"null")


def test_reads_and_security_headers(server):
    _, port = server
    st, ent = call(port, "GET", "/api/entity?id=project:skylr")
    assert st == 200 and ent["name"] == "Skylr" and ent["pending"]
    st, _ = call(port, "GET", "/api/stats", headers={"Host": "evil.example"})
    assert st == 403  # DNS rebinding
    st, _ = call(port, "GET", "/api/search?q=x&limit=abc")
    assert st == 400


def test_review_needs_header_origin_and_passphrase(server):
    lat, port = server
    pid = lat.list_proposals("pending")[0]["proposal_id"]
    st, _ = call(port, "POST", f"/api/proposals/{pid}/approve", {"passphrase": PW})
    assert st == 403  # no X-Lattice header (CSRF)
    st, _ = call(port, "POST", f"/api/proposals/{pid}/approve", {"passphrase": PW},
                 {"X-Lattice": "1", "Origin": "https://evil.example"})
    assert st == 403
    st, _ = call(port, "POST", f"/api/proposals/{pid}/approve", {"passphrase": "nope nope"}, {"X-Lattice": "1"})
    assert st == 401
    st, res = call(port, "POST", f"/api/proposals/{pid}/approve", {"passphrase": PW, "actor": "human:nobody"}, {"X-Lattice": "1"})
    assert st == 200 and res["status"] in ("applied", "pending", "invalid")
    assert lat.audit(PW)["ok"]
