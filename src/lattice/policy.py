"""Policy engines. A decision is a pure function of its recorded input.

Engines never read the database, files, network or clock. The core computes
everything a decision may depend on (the *input closure*) and records it, so
any decision can be replayed and must reproduce byte-identical output.

Two engine kinds:

* ``BuiltinEngine``: the reference policy, versioned ``lattice-py/1``.
* ``CommandEngine``: any executable that reads the input JSON on stdin and
  writes a decision JSON on stdout. This is the Skylr plug-in point.
  See docs/skylr-integration.md.
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Protocol

from .canonical import canonical_bytes, digest

INPUT_KIND = "lattice.dev/policy-input/v1"
DECISION_KIND = "lattice.dev/policy-decision/v1"
RANK = {"allow": 0, "review": 1, "deny": 2}


class Engine(Protocol):
    id: str

    def decide(self, policy_input: dict[str, Any]) -> dict[str, Any]: ...


def make_decision(engine_id: str, policy_input: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    findings = sorted(findings, key=lambda f: (-RANK[f["outcome"]], f["op_index"], f["rule_id"]))
    if findings and findings[0]["outcome"] != "allow":
        top = findings[0]
        outcome, rule_id, reason = top["outcome"], top["rule_id"], top["detail"]
    else:
        outcome, rule_id, reason = "allow", "default.allow", "No rule objected."
        if policy_input["plan"] and all(p["effect"] == "noop" for p in policy_input["plan"]):
            rule_id, reason = "noop.already_known", "Everything in this proposal is already known."
    return {
        "kind": DECISION_KIND,
        "engine": engine_id,
        "input_digest": digest(policy_input),
        "outcome": outcome,
        "rule_id": rule_id,
        "reason": reason,
        "findings": findings,
    }


def _days_before(ts: str, now: str) -> int:
    from datetime import date
    return (date.fromisoformat(now[:10]) - date.fromisoformat(ts[:10])).days


class BuiltinEngine:
    """Reference policy. Change the version string whenever semantics change."""

    id = "lattice-py/3"  # /3: registered voters, plan-bound votes, withdraw, no rate limit on re-decide

    def decide(self, inp: dict[str, Any]) -> dict[str, Any]:
        if inp.get("kind") != INPUT_KIND:
            raise ValueError("not a lattice policy input")
        actor, role = inp["actor"], inp["role"]
        approval = inp["approval"]
        # A human approval clears only the review findings that human actually saw.
        acknowledged = {(a["rule_id"], a["op_index"]) for a in approval.get("acknowledged", [])} \
            if approval["by"] and (approval["trust"] > actor["trust"] or approval["by"] == actor["id"]) else set()
        res = inp["resolution"]
        findings: list[dict[str, Any]] = []

        def find(rule: str, outcome: str, idx: int, detail: str) -> None:
            if outcome == "review" and (rule, idx) in acknowledged:
                return
            findings.append({"rule_id": rule, "outcome": outcome, "op_index": idx, "detail": detail})

        ops = inp["proposal"]["ops"]
        if len(ops) > role["max_ops_per_proposal"]:
            find("limits.ops", "deny", -1, f"{len(ops)} ops exceeds this role's limit of {role['max_ops_per_proposal']}; split the proposal.")
        if inp["aggregates"]["proposals_last_hour"] >= role["max_proposals_per_hour"] and not approval["by"] \
                and inp.get("trigger", "proposal") == "proposal":
            find("limits.rate", "deny", -1, f"Rate limit: {role['max_proposals_per_hour']} proposals/hour for role {actor['role']!r}.")

        for item in inp["plan"]:
            i, op = item["index"], item["op"]
            # "Own" means: about the actor's own entity AND not overruling anyone else's words.
            others = [c for c in item["closes"] + item["overlaps"] if c["actor"] != actor["id"]]
            own = item["target"] == actor["id"] and not others
            verdict = role["ops"][op]
            if verdict == "deny":
                find("role.op", "deny", i, f"Role {actor['role']!r} may not {op}.")
            elif verdict == "review" and not own:
                find("role.op", "review", i, f"Role {actor['role']!r} needs human review to {op}.")

            if op in ("endorse", "withdraw"):
                if item["instruction_like"]:
                    find("text.instruction_like", "review", i, "Endorsement reason reads like instructions to a model.")
                continue
            if op == "assert" and item["effect"] != "noop":
                if role["require_source"] and not item["has_source"]:
                    find("evidence.source_required", "deny", i, "Add a 'source' (URL, file, conversation or 'observed') to this assertion.")
                if item["confidence_bp"] < role["min_confidence_bp"] and not own:
                    find("evidence.low_confidence", "review", i,
                         f"Confidence {item['confidence_bp'] // 100} is below this role's minimum of {role['min_confidence_bp'] // 100} (scale 0-100).")
            if op == "assert" and item["effect"] == "insert" and item["cardinality"] == "one" and not own \
                    and item["owner_trust"] > actor["trust"]:
                find("trust.claim_slot", "review", i,
                     f"Sets a single-value fact on an entity created by a higher-trust actor (trust {item['owner_trust']} > {actor['trust']}).")
            if item["valid_from"] and item["effect"] != "noop" and actor["trust"] < 70 and _days_before(item["valid_from"], inp["now"]) > 365:
                find("temporal.backdated", "review", i, "valid_from is more than a year in the past; a human should confirm the history.")
            if item["overlaps"]:
                find("temporal.overlap", "review", i,
                     "Lands inside an earlier recorded interval (" + ", ".join(o["id"] for o in item["overlaps"]) + ") and would shorten it.")
            for closed in item["closes"]:
                if closed["trust"] > actor["trust"]:
                    find("trust.override", "review", i,
                         f"Would close {closed['id']} written by higher-trust {closed['actor']} (trust {closed['trust']} > {actor['trust']}).")
            if op == "create_entity" and item["best_match"]["id"]:
                score, other = item["best_match"]["score_bp"], item["best_match"]["id"]
                same_type = item["best_match"]["type"] == ops[i]["type"]
                if score >= res["duplicate_threshold_bp"] and same_type:
                    find("entity.duplicate", "deny", i, f"Looks like existing {other} ({score // 100}%). Use that id, or add an alias.")
                elif score >= res["review_threshold_bp"]:
                    kind = "" if same_type else f" (a {item['best_match']['type']})"
                    find("entity.near_duplicate", "review", i,
                         f"Close to existing {other}{kind} ({score // 100}%); a human should confirm it's different.")
            if item["instruction_like"]:
                find("text.instruction_like", "review", i, "Text reads like instructions to a model; a human should confirm it's knowledge, not an injection.")
        findings = self._consensus(inp, findings)
        return make_decision(self.id, inp, findings)

    @staticmethod
    def _consensus(inp: dict[str, Any], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Multi-vendor consensus can clear *eligible* review findings, like Skylr review rounds.

        Only owner-registered voters count, each pinned to one vendor; an approval counts only if it was cast
        on the exact plan being decided now (plan_digest); distinct vendors other than the proposer's must reach
        k; one registered objection blocks; and some findings always need a human (enforced by config)."""
        cons = inp.get("consensus")
        reviews = [f for f in findings if f["outcome"] == "review"]
        if not cons or not reviews or any(f["outcome"] == "deny" for f in findings):
            return findings
        voters = inp.get("voters", {})
        ops = inp["proposal"]["ops"]

        def key(f: dict[str, Any]) -> str:
            if f["rule_id"] == "role.op" and 0 <= f["op_index"] < len(ops):
                return f"role.op:{ops[f['op_index']]['op']}"
            return f["rule_id"]

        eligible = all(key(f) in cons["eligible"] for f in reviews)
        counted = [e for e in inp.get("endorsements", []) if e["actor"] in voters]
        objectors = sorted(e["actor"] for e in counted if e["verdict"] == "object")
        proposer_vendor = voters.get(inp["actor"]["id"], inp["actor"].get("vendor", "unknown"))
        vendors = sorted({voters[e["actor"]] for e in counted if e["verdict"] == "approve"
                          and e["plan"] == inp["plan_digest"] and voters[e["actor"]] != proposer_vendor})
        if objectors:
            return findings + [{"rule_id": "consensus.objection", "outcome": "review", "op_index": -1,
                                "detail": "Objected to by " + ", ".join(objectors) + "; a human decides."}]
        if not eligible or not voters:
            return findings
        if len(vendors) >= cons["k"]:
            return [f for f in findings if f["outcome"] != "review"] + [
                {"rule_id": "consensus.reached", "outcome": "allow", "op_index": -1,
                 "detail": f"Approved by {len(vendors)} vendors on plan {inp['plan_digest'][7:19]}: {', '.join(vendors)}."}]
        need = cons["k"] - len(vendors)
        return findings + [{"rule_id": "consensus.open", "outcome": "allow", "op_index": -1,
                            "detail": f"{need} more registered vendor(s) besides {proposer_vendor}"
                                      + (f" and {', '.join(vendors)}" if vendors else "")
                                      + f" can approve plan {inp['plan_digest'][7:19]} instead of a human."}]


@dataclass
class CommandEngine:
    """Runs an external decision provider over JSON stdin/stdout. Fails closed."""

    name: str
    argv: list[str]
    timeout_s: float = 10.0

    @property
    def id(self) -> str:
        return f"command:{self.name}"

    def decide(self, inp: dict[str, Any]) -> dict[str, Any]:
        try:
            proc = subprocess.run(
                self.argv, input=canonical_bytes(inp), capture_output=True, timeout=self.timeout_s, check=False
            )
            if proc.returncode != 0:
                raise RuntimeError(f"exit {proc.returncode}: {proc.stderr.decode(errors='replace')[:200]}")
            out = json.loads(proc.stdout)
            if out.get("outcome") not in RANK or not isinstance(out.get("rule_id"), str) or not isinstance(out.get("reason"), str) \
                    or not out["rule_id"] or not out["reason"]:
                raise RuntimeError("decision must contain outcome (allow|review|deny), rule_id and reason strings")
            findings = []
            for f in out.get("findings") or []:
                if not (isinstance(f, dict) and f.get("outcome") in RANK and isinstance(f.get("rule_id"), str)
                        and isinstance(f.get("detail"), str) and isinstance(f.get("op_index"), int) and not isinstance(f.get("op_index"), bool)):
                    raise RuntimeError("each finding needs rule_id, outcome, op_index (int) and detail")
                findings.append({k: f[k] for k in ("rule_id", "outcome", "op_index", "detail")})
            findings.append({"rule_id": out["rule_id"], "outcome": out["outcome"], "op_index": -1, "detail": out["reason"]})
            decision = make_decision(self.id, inp, findings)  # outcome = the worst of the stated outcome and findings
            canonical_bytes(decision)
            return decision
        except Exception as exc:  # noqa: BLE001 - every failure must fail closed
            return make_decision(self.id, inp, [{"rule_id": "engine.error", "outcome": "deny", "op_index": -1,
                                                 "detail": f"Engine failed, denying (fail closed): {exc}"}])


def timed_decide(engine: Engine, inp: dict[str, Any]) -> tuple[dict[str, Any], float]:
    t0 = time.perf_counter()
    d = engine.decide(inp)
    return d, (time.perf_counter() - t0) * 1000.0
