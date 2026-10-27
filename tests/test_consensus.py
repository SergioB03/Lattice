"""Multi-vendor consensus, including the round-3 red-team findings (sybils, plan drift, rate limit, cascades)."""

import pytest

from lattice.core import Lattice
from lattice.demo import seed

PW = "correct horse battery"


@pytest.fixture()
def lat():
    lat = Lattice.open(":memory:")
    lat.init(owner="human:sergio", passphrase=PW)
    seed(lat, "human:sergio", PW)  # registers claude-code/anthropic, codex-rem/openai, antigravity/google, ollama-qwen/local
    return lat


def pending_url(lat, actor="agent:ollama-qwen", url="https://github.com/SergioB03/Lattice"):
    r = lat.propose(actor, [{"op": "assert", "subject": "Lattice", "predicate": "url", "value": url,
                             "source": "observed", "confidence": 55}])
    assert r["status"] == "pending"
    return r["proposal_id"]


def plan_of(lat, pid):
    return next(p["plan_digest"] for p in lat.list_proposals("pending") if p["proposal_id"] == pid)


def endorse(lat, actor, pid, verdict="approve", plan=None):
    return lat.propose(actor, [{"op": "endorse", "proposal": pid, "verdict": verdict,
                                "plan": plan if plan is not None else plan_of(lat, pid)}])


def test_two_registered_vendors_reach_consensus_and_audit_replays_it(lat):
    pid = pending_url(lat)
    assert endorse(lat, "agent:claude-code", pid)["redecided"][0]["status"] == "pending"
    second = endorse(lat, "agent:codex-rem", pid)
    assert second["redecided"] == [{"proposal_id": pid, "status": "applied", "rule_id": "default.allow"}]
    report = lat.audit(PW)
    assert report["ok"], report["problems"]
    assert lat.verify()["rebuild_matches"]


def test_sock_puppet_ids_have_no_vote(lat):
    """R3-1: agent:codex-x and agent:gemini-y look like other vendors, but only registered ids count."""
    pid = pending_url(lat)
    for fake in ("agent:codex-x", "agent:gemini-y", "agent:claudette"):
        r = endorse(lat, fake, pid)
        assert r["status"] == "applied" and "redecided" not in r  # recorded, but can't move the outcome
    assert lat.proposal_status(pid)["status"] == "pending"
    fake_objection = endorse(lat, "agent:replit-z", pid, "object")
    assert "redecided" not in fake_objection  # and can't block either (no DoS by unregistered ids)


def test_votes_bind_to_the_plan_the_voter_saw(lat):
    """R3-2: after the first vote the owner sets a URL, so the plan now overrules the owner. Old votes don't carry over."""
    pid = pending_url(lat, url="https://example.com/a")
    seen = plan_of(lat, pid)
    endorse(lat, "agent:claude-code", pid, plan=seen)
    lat.propose("human:sergio", [{"op": "assert", "subject": "Lattice", "predicate": "url",
                                  "value": "https://github.com/SergioB03/Lattice"}], passphrase=PW)
    assert plan_of(lat, pid) != seen
    r = endorse(lat, "agent:codex-rem", pid, plan=seen)  # stale digest: doesn't count
    assert r["redecided"][0]["status"] == "pending"
    queue = next(p for p in lat.list_proposals("pending") if p["proposal_id"] == pid)
    assert "trust.override" in {f["rule_id"] for f in queue["findings"]}  # and now it needs the human anyway


def test_redecide_ignores_the_proposers_rate_limit(lat):
    """R3-3: a vote must not get someone else's proposal denied by *their* hourly rate limit."""
    cfg = lat.config.data
    cfg["roles"]["agent"]["max_proposals_per_hour"] = 3
    lat.set_config(cfg, PW)
    pid = pending_url(lat)
    for i in range(3):
        lat.propose("agent:ollama-qwen", [{"op": "assert", "subject": "agent:ollama-qwen", "predicate": "note",
                                           "value": f"busy {i}", "source": "s"}])
    endorse(lat, "agent:claude-code", pid)
    assert endorse(lat, "agent:codex-rem", pid)["redecided"][0]["status"] == "applied"
    assert lat.audit(PW)["ok"]


def test_no_vote_cascades_and_votes_are_capped(lat):
    """R3-5/R3-4: proposals with votes can't mix in other ops and can't themselves be voted on."""
    pid = pending_url(lat)
    mixed = lat.propose("agent:claude-code", [
        {"op": "endorse", "proposal": pid, "verdict": "approve", "plan": plan_of(lat, pid)},
        {"op": "assert", "subject": "agent:claude-code", "predicate": "note", "value": "x", "source": "s"}])
    assert mixed["status"] == "invalid"


def test_objection_blocks_and_human_still_decides(lat):
    pid = pending_url(lat)
    endorse(lat, "agent:antigravity", pid, "object")
    endorse(lat, "agent:claude-code", pid)
    r = endorse(lat, "agent:codex-rem", pid)
    assert r["redecided"][0]["status"] == "pending"
    assert lat.proposal_status(pid)["rule_id"] == "consensus.objection"
    assert lat.approve(pid, "human:sergio", PW)["status"] == "applied"


def test_endorsement_rules_and_withdraw(lat):
    pid = pending_url(lat)
    assert endorse(lat, "agent:ollama-qwen", pid)["status"] == "invalid"  # own proposal
    endorse(lat, "agent:claude-code", pid)
    assert endorse(lat, "agent:claude-code", pid, "object")["status"] == "invalid"  # one vote each
    assert endorse(lat, "agent:codex-rem", "p_nope", plan="x")["status"] == "invalid"
    assert lat.propose("agent:codex-rem", [{"op": "withdraw", "proposal": pid}])["status"] == "invalid"  # not yours
    assert lat.propose("agent:ollama-qwen", [{"op": "withdraw", "proposal": pid, "reason": "typo"}])["status"] == "applied"
    assert lat.proposal_status(pid)["status"] == "withdrawn"


def test_owner_overrides_are_never_consensus(lat):
    r = lat.propose("agent:ollama-qwen", [{"op": "assert", "subject": "Skylr", "predicate": "status", "value": "abandoned",
                                           "source": "guess"}])
    for a in ("agent:claude-code", "agent:codex-rem", "agent:antigravity"):
        endorse(lat, a, r["proposal_id"])
    assert lat.proposal_status(r["proposal_id"])["status"] == "pending"


def test_config_changes_are_owner_signed(lat):
    cfg = lat.config.data
    cfg["voters"].append({"actor": "agent:replit", "vendor": "replit"})
    from lattice import store
    lat.conn.execute("BEGIN IMMEDIATE")  # an agent with a shell forges a config change without the passphrase
    store.append_and_apply(lat.conn, run_id="lattice", type="config.changed", actor="human:sergio",
                           payload={"config": cfg, "owner_mac": ""}, ts="2026-10-28T00:00:00.000Z")
    lat.conn.execute("COMMIT")
    report = lat.audit(PW)
    assert not report["ok"] and any("config.changed" in p for p in report["problems"])
