import pytest

from lattice.core import Lattice
from lattice.demo import seed

PW = "correct horse battery"


@pytest.fixture()
def lat():
    lat = Lattice.open(":memory:")
    lat.init(owner="human:sergio", passphrase=PW)
    seed(lat, "human:sergio", PW)
    return lat


def pending_url(lat, actor="agent:ollama-qwen"):
    r = lat.propose(actor, [{"op": "assert", "subject": "Lattice", "predicate": "url",
                             "value": "https://github.com/SergioB03/Lattice", "source": "observed", "confidence": 55}])
    assert r["status"] == "pending"
    return r["proposal_id"]


def endorse(lat, actor, pid, verdict="approve", reason=""):
    return lat.propose(actor, [{"op": "endorse", "proposal": pid, "verdict": verdict, "reason": reason}])


def test_two_vendors_reach_consensus_and_audit_replays_it(lat):
    pid = pending_url(lat)
    first = endorse(lat, "agent:claude-code", pid)
    assert first["status"] == "applied" and first["redecided"][0]["status"] == "pending"
    second = endorse(lat, "agent:codex-rem", pid)
    assert second["redecided"] == [{"proposal_id": pid, "status": "applied", "rule_id": "default.allow"}]
    assert [f["value"] for f in lat.facts("project:lattice") if f["predicate"] == "url"] == ["https://github.com/SergioB03/Lattice"]
    report = lat.audit(PW)
    assert report["ok"], report["problems"]
    assert lat.verify()["rebuild_matches"]


def test_same_vendor_twice_is_one_voice(lat):
    pid = pending_url(lat)
    endorse(lat, "agent:claude-code", pid)
    r = endorse(lat, "agent:claude-reviewer", pid)
    assert r["redecided"][0]["status"] == "pending"


def test_proposer_vendor_does_not_count(lat):
    pid = pending_url(lat, actor="agent:codex-rem")
    endorse(lat, "agent:codex-helper", pid)
    r = endorse(lat, "agent:claude-code", pid)
    assert r["redecided"][0]["status"] == "pending"
    r = endorse(lat, "agent:antigravity", pid)
    assert r["redecided"][0]["status"] == "applied"


def test_objection_blocks_and_human_still_decides(lat):
    pid = pending_url(lat)
    endorse(lat, "agent:antigravity", pid, "object", "wrong URL casing")
    endorse(lat, "agent:claude-code", pid)
    r = endorse(lat, "agent:codex-rem", pid)
    assert r["redecided"][0]["status"] == "pending"
    assert lat.proposal_status(pid)["rule_id"] == "consensus.objection"
    assert lat.approve(pid, "human:sergio", PW)["status"] == "applied"


def test_endorsement_rules(lat):
    pid = pending_url(lat)
    assert endorse(lat, "agent:ollama-qwen", pid)["status"] == "invalid"  # own proposal
    endorse(lat, "agent:claude-code", pid)
    assert endorse(lat, "agent:claude-code", pid, "object")["status"] == "invalid"  # one vote each
    assert endorse(lat, "agent:codex-rem", "p_nope")["status"] == "invalid"


def test_owner_overrides_are_never_consensus(lat):
    r = lat.propose("agent:ollama-qwen", [{"op": "assert", "subject": "Skylr", "predicate": "status", "value": "abandoned",
                                           "source": "guess"}])
    for a in ("agent:claude-code", "agent:codex-rem", "agent:antigravity", "agent:replit"):
        endorse(lat, a, r["proposal_id"])
    assert lat.proposal_status(r["proposal_id"])["status"] == "pending"
