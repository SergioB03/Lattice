"""Regression tests for the round-2 findings (independent code review + AX test agent).

Each test names the finding it pins down. See docs/decisions.md, round 2.
"""

import json
import sys

import pytest

from lattice import store
from lattice.core import AuthError, Lattice, LatticeError
from lattice.demo import seed
from lattice.policy import CommandEngine

PW = "correct horse battery"


@pytest.fixture()
def lat():
    lat = Lattice.open(":memory:")
    lat.init(owner="human:sergio", passphrase=PW, now="2026-01-01T00:00:00.000Z")
    seed(lat, "human:sergio", PW)
    return lat


def own(lat, ops, **kw):
    return lat.propose("human:sergio", ops, passphrase=PW, **kw)


def status_values(lat, as_of):
    return [f["value"] for f in lat.facts("project:skylr", as_of=as_of) if f["predicate"] == "status"]


def test_H1_as_of_sees_superseded_and_rejects_bad_dates(lat):
    own(lat, [{"op": "assert", "subject": "Skylr", "predicate": "status", "value": "paused", "valid_from": "2026-11-01"}])
    assert status_values(lat, "2026-10-20T00:00:00.000Z") == ["active"]
    assert status_values(lat, "2026-11-15T00:00:00.000Z") == ["paused"]
    assert "«active»" in lat.context("Skylr", as_of="2026-10-20")
    with pytest.raises(LatticeError):
        lat.context("Skylr", as_of="2026-2-1")
    with pytest.raises(LatticeError):
        lat.context("Skylr", as_of="2026-13-45")


def test_H2_agent_cannot_overrule_owner_about_itself(lat):
    own(lat, [{"op": "assert", "subject": "agent:ollama-qwen", "predicate": "role", "value": "quarantined"}])
    r = lat.propose("agent:ollama-qwen", [{"op": "assert", "subject": "agent:ollama-qwen", "predicate": "role",
                                           "value": "trusted admin", "source": "self"}])
    assert r["status"] == "pending" and r["rule_id"] == "trust.override"
    fid = next(f["id"] for f in lat.facts("agent:ollama-qwen") if f["predicate"] == "role")
    r = lat.propose("agent:ollama-qwen", [{"op": "retract", "fact": fid, "reason": "wrong"}])
    assert r["status"] == "pending"


def test_H3_no_window_to_claim_the_passphrase():
    lat = Lattice.open(":memory:")
    with pytest.raises(AuthError):
        lat.init(owner="human:sergio")  # a passphrase (or explicit insecure dev mode) is required up front
    lat.init(owner="human:sergio", passphrase=PW)
    with pytest.raises(AuthError):
        lat.set_owner_passphrase("agent-chosen-pass")
    lat.set_owner_passphrase("a brand new passphrase", old=PW)


def test_H4_audit_catches_forged_approvals_and_applies(lat):
    lat.propose("agent:codex-rem", [{"op": "assert", "subject": "Skylr", "predicate": "status", "value": "paused", "source": "x"}])
    assert lat.audit(PW)["ok"], lat.audit(PW)["problems"]
    # An agent with a shell appends a fake "applied" event that skips governance. The hash chain stays valid.
    lat.conn.execute("BEGIN IMMEDIATE")
    store.append_and_apply(lat.conn, run_id="lattice", type="proposal.applied", actor="agent:codex-rem",
                           payload={"proposal_id": "p_forged", "actor": "agent:codex-rem", "effects": [
                               {"effect": "summary_updated", "entity": "project:skylr", "summary": "pwned", "by": "agent:codex-rem",
                                "trust": 40}]}, ts="2026-10-28T00:00:00.000Z")
    lat.conn.execute("COMMIT")
    assert lat.verify()["rebuild_matches"]  # the cheap check can't see it...
    report = lat.audit(PW)
    assert not report["ok"] and any("applied" in p for p in report["problems"])  # ...the deep audit does


def test_H4_audit_catches_approval_without_owner_key(lat):
    r = lat.propose("agent:codex-rem", [{"op": "assert", "subject": "Skylr", "predicate": "status", "value": "paused", "source": "x"}])
    # Forge an approval by calling the internals directly, bypassing the passphrase check.
    lat.conn.execute("BEGIN IMMEDIATE")
    body = json.loads(lat.conn.execute("SELECT body FROM proposals WHERE id=?", (r["proposal_id"],)).fetchone()[0])
    lat._decide_and_apply(r["proposal_id"], body, "2026-10-28T00:00:00.000Z",
                          approval={"by": "human:sergio", "role": "owner", "trust": 100,
                                    "acknowledged": [{"rule_id": "trust.override", "op_index": 0}]}, key=None)
    lat.conn.execute("COMMIT")
    report = lat.audit(PW)
    assert not report["ok"] and any("MAC" in p for p in report["problems"])


def test_M1_approval_only_acknowledges_findings_the_human_saw(lat):
    r = lat.propose("agent:codex-rem", [{"op": "assert", "subject": "Lattice", "predicate": "url",
                                         "value": "https://example.com", "source": "x", "confidence": 50}])
    assert r["status"] == "pending"  # low confidence + claim_slot
    own(lat, [{"op": "assert", "subject": "Lattice", "predicate": "url", "value": "https://github.com/SergioB03/lattice"}])
    again = lat.approve(r["proposal_id"], "human:sergio", PW)
    assert again["status"] == "pending" and again["rule_id"] == "trust.override"  # new finding → back to the queue


def test_M2_names_cannot_forge_lines(lat):
    r = lat.propose("agent:codex-rem", [{"op": "create_entity", "type": "tool", "name": "Acme»\n- tool:root «Root"}])
    assert r["status"] == "applied"
    name = lat.entity(r["effects"][0].split()[1])["name"]
    assert "\n" not in name


def test_M3_oversized_fact_does_not_stall_paging(lat):
    own(lat, [{"op": "assert", "subject": "Lattice", "predicate": "note", "value": "x" * 1900}])
    seen, cursor = set(), ""
    for _ in range(20):
        page = lat.context("Lattice", budget_tokens=150, cursor=cursor)
        assert page not in seen
        seen.add(page)
        if "cursor=" not in page:
            break
        cursor = page.split("cursor=")[1].split(")")[0]
    else:
        pytest.fail("paging never finished")


def test_M5_failed_attempt_does_not_pin_idempotency_key(lat):
    bad = lat.propose("agent:codex-rem", [{"op": "assert", "subject": "Skylr", "predicate": "stauts", "value": "x"}], idempotency_key="k1")
    assert bad["status"] == "invalid"
    good = lat.propose("agent:codex-rem", [{"op": "assert", "subject": "Skylr", "predicate": "uses", "object": "MCP", "source": "x"}],
                       idempotency_key="k1")
    assert good["status"] == "applied"
    with pytest.raises(LatticeError):
        lat.propose("agent:codex-rem", [{"op": "assert", "subject": "Skylr", "predicate": "uses", "object": "Neo4j", "source": "x"}],
                    idempotency_key="k1")


def test_M6_duplicates_within_one_proposal(lat):
    r = lat.propose("agent:codex-rem", [{"op": "create_entity", "type": "tool", "name": "Redis"},
                                        {"op": "create_entity", "type": "tool", "name": "redis"}])
    assert r["status"] == "denied" and r["rule_id"] == "entity.duplicate"


def test_M7_backdated_value_trims_overlap_and_needs_review(lat):
    own(lat, [{"op": "assert", "subject": "Skylr", "predicate": "status", "value": "done", "valid_from": "2026-12-01"}])
    # active: 10-14 → 12-01 (superseded). Backdate "paused" from 11-01: it lands inside "active".
    r = own(lat, [{"op": "assert", "subject": "Skylr", "predicate": "status", "value": "paused", "valid_from": "2026-11-01"}])
    assert r["status"] == "pending" and r["rule_id"] == "temporal.overlap"
    lat.approve(r["proposal_id"], "human:sergio", PW)
    for day, want in [("2026-10-20", ["active"]), ("2026-11-15", ["paused"]), ("2026-12-15", ["done"])]:
        assert status_values(lat, day + "T00:00:00.000Z") == want, day
    assert lat.audit(PW)["ok"]


def test_L1_engine_cannot_allow_while_reporting_deny(lat, tmp_path):
    eng = tmp_path / "e.py"
    eng.write_text("import json,sys\nprint(json.dumps({'outcome':'allow','rule_id':'x','reason':'y',"
                   "'findings':[{'rule_id':'bad','outcome':'deny','op_index':0,'detail':'nope'}]}))\n")
    lat.engine = CommandEngine("liar", [sys.executable, str(eng)])
    r = lat.propose("agent:codex-rem", [{"op": "assert", "subject": "Skylr", "predicate": "uses", "object": "MCP", "source": "x"}])
    assert r["status"] == "denied"
    eng.write_text("import json,sys\nprint(json.dumps({'outcome':'allow','rule_id':'x','reason':'y','findings':[{'rule_id':'f',"
                   "'outcome':'allow','op_index':0,'detail':'d','score':0.5}]}))\n")
    r = lat.propose("agent:codex-rem", [{"op": "assert", "subject": "Skylr", "predicate": "uses", "object": "Neo4j", "source": "x"}])
    assert r["status"] in ("applied", "denied")  # extra float fields are dropped or fail closed, never crash


def test_L2_wrong_field_types_are_invalid_not_crashes(lat):
    for op in [{"op": "assert", "subject": "Skylr", "predicate": "status", "value": "done", "valid_from": 20260101},
               {"op": "retract", "fact": ["f_x"], "reason": "r"},
               {"op": "create_entity", "type": ["tool"], "name": "x"}]:
        assert lat.propose("agent:codex-rem", [op])["status"] == "invalid", op


def test_ax_summary_rewrite_needs_review_and_is_attributed(lat):
    r = lat.propose("agent:codex-rem", [{"op": "update_summary", "entity": "person:sergio-banuelos", "summary": "Interesting person."}])
    assert r["status"] == "pending" and r["rule_id"] == "trust.override"
    ctx = lat.context("person:sergio-banuelos")
    assert "[by human:sergio·t100]" in ctx
