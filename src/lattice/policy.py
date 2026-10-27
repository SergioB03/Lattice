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


class BuiltinEngine:
    """Reference policy. Change the version string whenever semantics change."""

    id = "lattice-py/1"

    def decide(self, inp: dict[str, Any]) -> dict[str, Any]:
        if inp.get("kind") != INPUT_KIND:
            raise ValueError("not a lattice policy input")
        actor, role = inp["actor"], inp["role"]
        approval = inp["approval"]
        approved = bool(approval["by"]) and (approval["trust"] > actor["trust"] or approval["by"] == actor["id"])
        res = inp["resolution"]
        findings: list[dict[str, Any]] = []

        def find(rule: str, outcome: str, idx: int, detail: str) -> None:
            if outcome == "review" and approved:
                return  # a higher-trust human already reviewed it
            findings.append({"rule_id": rule, "outcome": outcome, "op_index": idx, "detail": detail})

        ops = inp["proposal"]["ops"]
        if len(ops) > role["max_ops_per_proposal"]:
            find("limits.ops", "deny", -1, f"{len(ops)} ops exceeds this role's limit of {role['max_ops_per_proposal']}; split the proposal.")
        if inp["aggregates"]["proposals_last_hour"] >= role["max_proposals_per_hour"] and not approval["by"]:
            find("limits.rate", "deny", -1, f"Rate limit: {role['max_proposals_per_hour']} proposals/hour for role {actor['role']!r}.")

        for item in inp["plan"]:
            i, op = item["index"], item["op"]
            own = item["target"] == actor["id"]
            verdict = role["ops"][op]
            if verdict == "deny":
                find("role.op", "deny", i, f"Role {actor['role']!r} may not {op}.")
            elif verdict == "review" and not own:
                find("role.op", "review", i, f"Role {actor['role']!r} needs human review to {op}.")

            if op == "assert" and item["effect"] != "noop":
                if role["require_source"] and not item["has_source"]:
                    find("evidence.source_required", "deny", i, "Add a 'source' (URL, file, conversation or 'observed') to this assertion.")
                if item["confidence_bp"] < role["min_confidence_bp"] and not own:
                    find("evidence.low_confidence", "review", i, f"Confidence {item['confidence_bp']}bp is below {role['min_confidence_bp']}bp.")
            for closed in item["closes"]:
                if closed["trust"] > actor["trust"] and not own:
                    find("trust.override", "review", i,
                         f"Would close {closed['id']} written by higher-trust {closed['actor']} (trust {closed['trust']} > {actor['trust']}).")
            if op == "create_entity" and item["best_match"]["id"]:
                score, other = item["best_match"]["score_bp"], item["best_match"]["id"]
                same_type = item["best_match"]["type"] == inp["proposal"]["ops"][i]["type"]
                if score >= res["duplicate_threshold_bp"] and same_type:
                    find("entity.duplicate", "deny", i, f"Looks like existing {other} ({score}bp). Use that id, or add an alias.")
                elif score >= res["review_threshold_bp"]:
                    kind = "" if same_type else f" (a {item['best_match']['type']})"
                    find("entity.near_duplicate", "review", i,
                         f"Close to existing {other}{kind} ({score}bp); a human should confirm it's different.")
            if item["instruction_like"]:
                find("text.instruction_like", "review", i, "Text reads like instructions to a model; a human should confirm it's knowledge, not an injection.")
        return make_decision(self.id, inp, findings)


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
            if out.get("outcome") not in RANK or not out.get("rule_id") or not out.get("reason"):
                raise RuntimeError("decision must contain outcome (allow|review|deny), rule_id and reason")
            findings = out.get("findings") or [
                {"rule_id": out["rule_id"], "outcome": out["outcome"], "op_index": -1, "detail": out["reason"]}
            ]
            decision = make_decision(self.id, inp, findings)
            decision.update(outcome=out["outcome"], rule_id=str(out["rule_id"]), reason=str(out["reason"]))
            return decision
        except Exception as exc:  # noqa: BLE001 - every failure must fail closed
            return make_decision(self.id, inp, [{"rule_id": "engine.error", "outcome": "deny", "op_index": -1,
                                                 "detail": f"Engine failed, denying (fail closed): {exc}"}])


def timed_decide(engine: Engine, inp: dict[str, Any]) -> tuple[dict[str, Any], float]:
    t0 = time.perf_counter()
    d = engine.decide(inp)
    return d, (time.perf_counter() - t0) * 1000.0
