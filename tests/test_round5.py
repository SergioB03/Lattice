"""Regression tests for the round-5 pre-release review."""

import json
import subprocess
import sys

import pytest

from lattice import store
from lattice.core import AuthError, Lattice, LatticeError
from lattice.demo import seed

PW = "correct horse battery"


@pytest.fixture()
def lat():
    lat = Lattice.open(":memory:")
    lat.init(owner="human:sergio", passphrase=PW)
    seed(lat, "human:sergio", PW)
    return lat


def forge(lat, type_, actor, payload, ts=None):
    lat.conn.execute("BEGIN IMMEDIATE")
    ts = ts or lat.conn.execute("SELECT ts FROM events ORDER BY seq DESC LIMIT 1").fetchone()[0]
    ev = store.append_and_apply(lat.conn, run_id="lattice", type=type_, actor=actor, payload=payload, ts=ts)
    lat.conn.execute("COMMIT")
    return ev


def test_F1_owner_signature_covers_the_whole_body(lat):
    r = lat.propose("human:sergio", [{"op": "assert", "subject": "Lattice", "predicate": "note", "value": "real"}], passphrase=PW)
    row = lat.conn.execute("SELECT payload FROM events WHERE type='proposal.received' ORDER BY seq DESC LIMIT 1").fetchone()
    payload = json.loads(bytes(row[0]))
    assert payload["id"] == r["proposal_id"]
    payload["proposal"]["ops"][0]["value"] = "swapped by an attacker"
    payload["id"] = "p_forged000000"
    forge(lat, "proposal.received", "human:sergio", payload)
    problems = lat.audit(PW)["problems"]
    assert any("content digest" in p for p in problems) and any("MAC" in p for p in problems)


def test_F2_genesis_is_signed():
    lat = Lattice.open(":memory:")
    lat.init(owner="human:sergio", passphrase=PW)
    assert lat.audit(PW)["ok"]
    g = json.loads(bytes(lat.conn.execute("SELECT payload FROM events WHERE seq=1").fetchone()[0]))
    g["config"]["roles"]["agent"]["trust"] = 100  # rewrite roles, keep the passphrase hash
    fresh = Lattice.open(":memory:")
    forge(fresh, "lattice.initialized", "human:sergio", g, ts="2026-10-27T00:00:00.000Z")
    problems = fresh.audit(PW)["problems"]
    assert any("genesis" in p for p in problems)


def test_F3_engine_is_config_not_a_flag(tmp_path):
    db = tmp_path / "g.db"
    r = subprocess.run([sys.executable, "-m", "lattice.cli", "--db", str(db), "--engine", "x", "stats"],
                       capture_output=True, text=True, check=False)
    assert r.returncode != 0  # the flag no longer exists
    lat = Lattice.open(db)
    lat.init(owner="human:sergio", passphrase=PW)
    script = tmp_path / "yes.py"
    script.write_text("import json;print(json.dumps({'outcome':'allow','rule_id':'yes','reason':'yes'}))\n")
    data = lat.config.data
    data["engine"] = {"kind": "command", "name": "yes", "argv": [sys.executable, str(script)]}
    with pytest.raises(AuthError):
        lat.set_config(data, "wrong passphrase")
    lat.set_config(data, PW)
    assert lat.engine.id.startswith("command:yes@")
    assert lat.audit(PW)["ok"]


def test_F4_audit_checks_the_decision_clock(lat):
    r = lat.propose("agent:codex-rem", [{"op": "assert", "subject": "Skylr", "predicate": "uses", "object": "MCP", "source": "x"}])
    dec = json.loads(bytes(lat.conn.execute("SELECT payload FROM events WHERE type='decision.recorded' ORDER BY seq DESC LIMIT 1").fetchone()[0]))
    assert dec["input"]["now"] == lat.conn.execute("SELECT ts FROM events WHERE type='decision.recorded' ORDER BY seq DESC LIMIT 1").fetchone()[0]
    assert lat.audit(PW)["ok"]
    forge(lat, "proposal.received", "agent:codex-rem", {"id": "p_x", "content_digest": "sha256:" + "0" * 64,
                                                         "proposal": json.loads(lat.conn.execute("SELECT body FROM proposals WHERE id=?", (r["proposal_id"],)).fetchone()[0])},
          ts="2015-01-01T00:00:00.000Z")
    assert any("backwards" in p for p in lat.audit(PW)["problems"])


def test_F5_size_limits_before_anything_is_written(lat):
    head = lat.head()
    with pytest.raises(LatticeError):
        lat.propose("agent:codex-rem", [{"op": "assert", "subject": "Skylr", "predicate": "note", "value": "x" * 300_000}])
    with pytest.raises(LatticeError):
        lat.propose("agent:codex-rem", [{"op": "assert", "subject": "Skylr", "predicate": "note", "value": "x"}] * 201)
    deep: dict = {}
    cur = deep
    for _ in range(50):
        cur["x"] = {}
        cur = cur["x"]
    with pytest.raises(LatticeError):
        lat.propose("agent:codex-rem", [{"op": "assert", "subject": "Skylr", "predicate": "note", "value": "x", "evidence": deep}])
    assert lat.head() == head  # nothing reached the append-only ledger


def test_F6_pre_1900_dates_are_rejected(lat):
    r = lat.propose("human:sergio", [{"op": "assert", "subject": "Lattice", "predicate": "status", "value": "idea",
                                      "valid_from": "0999-01-01"}], passphrase=PW)
    assert r["status"] == "invalid"
    assert [f["value"] for f in lat.facts("project:lattice") if f["predicate"] == "status"] == ["active"]


def test_F7_backdated_slot_and_empty_summary_need_review(lat):
    r = lat.propose("agent:codex-rem", [{"op": "assert", "subject": "Lattice", "predicate": "status", "value": "abandoned",
                                         "valid_from": "2026-03-01", "source": "x"}])
    assert r["status"] == "pending"
    r = lat.propose("agent:codex-rem", [{"op": "update_summary", "entity": "tool:neo4j", "summary": "Deprecated."}])
    assert r["status"] == "pending" and r["rule_id"] == "trust.claim_slot"


def test_F8_approval_refuses_a_decision_the_owner_did_not_see(lat):
    item = lat.list_proposals("pending")[0]
    with pytest.raises(LatticeError):
        lat.approve(item["proposal_id"], "human:sergio", PW, seen_decision="sha256:" + "1" * 64)
    assert lat.approve(item["proposal_id"], "human:sergio", PW, seen_decision=item["decision_digest"])["status"] in (
        "applied", "pending", "invalid")


def test_punctuation_only_names_are_invalid(lat):
    assert lat.propose("agent:codex-rem", [{"op": "create_entity", "type": "concept", "name": "!!!"}])["status"] == "invalid"
