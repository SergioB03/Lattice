"""Actors, roles and policy settings (the governed configuration).

The configuration is stored in the database as canonical JSON and its digest
goes into every policy decision, so changing a role can't silently change how
old decisions replay.
"""

from __future__ import annotations

import copy
import fnmatch
import re
from dataclasses import dataclass
from typing import Any

from .canonical import digest

ACTOR_RE = re.compile(r"^(human|agent|service):[a-z0-9][a-z0-9._-]{0,63}$")
OPS = ("create_entity", "assert", "retract", "add_alias", "update_summary", "define_type", "define_predicate", "endorse",
       "withdraw")
OUTCOMES = ("allow", "review", "deny")

DEFAULT_CONFIG: dict[str, Any] = {
    "version": 1,
    "roles": {
        "owner": {
            "trust": 100,
            "ops": {op: "allow" for op in OPS},
            "max_ops_per_proposal": 200,
            "max_proposals_per_hour": 1000,
            "require_source": False,
            "min_confidence_bp": 0,
        },
        "maintainer": {
            "trust": 70,
            "ops": {**{op: "allow" for op in OPS}, "define_type": "review", "define_predicate": "review"},
            "max_ops_per_proposal": 100,
            "max_proposals_per_hour": 300,
            "require_source": False,
            "min_confidence_bp": 0,
        },
        "agent": {
            "trust": 40,
            "ops": {
                "create_entity": "allow",
                "assert": "allow",
                "retract": "review",
                "add_alias": "review",
                "update_summary": "allow",
                "define_type": "review",
                "define_predicate": "review",
                "endorse": "allow",
                "withdraw": "allow",
            },
            "max_ops_per_proposal": 25,
            "max_proposals_per_hour": 120,
            "require_source": True,
            "min_confidence_bp": 6000,
        },
        "observer": {
            "trust": 10,
            "ops": {op: "deny" for op in OPS},
            "max_ops_per_proposal": 0,
            "max_proposals_per_hour": 0,
            "require_source": True,
            "min_confidence_bp": 10000,
        },
    },
    # First match wins. Patterns use shell-style wildcards.
    "actors": [
        {"match": "human:owner", "role": "owner"},
        {"match": "human:*", "role": "maintainer"},
        {"match": "agent:*", "role": "agent"},
        {"match": "service:*", "role": "observer"},
    ],
    "resolution": {"duplicate_threshold_bp": 9500, "review_threshold_bp": 8500},
    # Which policy engine decides. Part of the owner-signed config so nobody can swap it per command.
    # {"kind": "command", "name": "skylr", "argv": ["skylr", "graph", "evaluate"], "timeout_s": 10}
    "engine": {"kind": "builtin"},
    # Which company/runtime an agent belongs to. Consensus counts *vendors*, not agents,
    # so three Claude instances agreeing is one voice. First match wins.
    "vendors": [
        {"match": "human:*", "vendor": "human"},
        {"match": "agent:claude*", "vendor": "anthropic"},
        {"match": "agent:codex*", "vendor": "openai"},
        {"match": "agent:gpt*", "vendor": "openai"},
        {"match": "agent:antigravity*", "vendor": "google"},
        {"match": "agent:gemini*", "vendor": "google"},
        {"match": "agent:jules*", "vendor": "google"},
        {"match": "agent:replit*", "vendor": "replit"},
        {"match": "agent:copilot*", "vendor": "github"},
        {"match": "agent:ollama*", "vendor": "local"},
        {"match": "agent:local*", "vendor": "local"},
    ],
    # Voting needs registration: actor ids aren't authenticated, so only exact ids the owner registered
    # (each pinned to a vendor) are counted. Empty means consensus is off. Change with `lattice voters add`.
    "voters": [],
    # Multi-vendor consensus can stand in for a human on these review findings only. Overruling a
    # higher-trust author, suspected injection and history rewrites always need a human.
    "consensus": {
        "k": 2,
        "eligible": [
            "evidence.low_confidence",
            "trust.claim_slot",
            "entity.near_duplicate",
            "temporal.backdated",
            "role.op:retract",
            "role.op:add_alias",
        ],
    },
}
NEVER_CONSENSUS = ("trust.override", "text.instruction_like", "temporal.overlap", "role.op:define_type", "role.op:define_predicate")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Actor:
    id: str
    role: str
    trust: int
    vendor: str = "unknown"

    def to_json(self) -> dict[str, Any]:
        return {"id": self.id, "role": self.role, "trust": self.trust, "vendor": self.vendor}


def validate_actor_id(actor: str) -> str:
    if not isinstance(actor, str) or not ACTOR_RE.match(actor):
        raise ConfigError(
            f"invalid actor id {actor!r}: use human:<name>, agent:<name> or service:<name> "
            "(lowercase letters, digits, . _ -)"
        )
    return actor


class Config:
    def __init__(self, data: dict[str, Any]):
        self.data = copy.deepcopy(data)
        self._validate()

    def _validate(self) -> None:
        d = self.data
        if d.get("version") != 1:
            raise ConfigError("config version must be 1")
        roles = d.get("roles")
        if not isinstance(roles, dict) or not roles:
            raise ConfigError("config needs roles")
        for name, r in roles.items():
            need = {"trust", "ops", "max_ops_per_proposal", "max_proposals_per_hour", "require_source", "min_confidence_bp"}
            if set(r) != need:
                raise ConfigError(f"role {name!r} must define exactly {sorted(need)}")
            if set(r["ops"]) != set(OPS) or any(v not in OUTCOMES for v in r["ops"].values()):
                raise ConfigError(f"role {name!r} must map every op {OPS} to one of {OUTCOMES}")
            if not (0 <= r["trust"] <= 100):
                raise ConfigError("trust must be 0..100")
        for rule in d.get("actors", []):
            if rule.get("role") not in roles:
                raise ConfigError(f"actor rule {rule} names an unknown role")
        for rule in d.get("vendors", []):
            if set(rule) != {"match", "vendor"} or not str(rule["vendor"]).isidentifier():
                raise ConfigError(f"vendor rule {rule} needs match and a simple vendor name")
        eng = d.get("engine", {"kind": "builtin"})
        if eng.get("kind") == "command":
            if set(eng) - {"kind", "name", "argv", "timeout_s"} or not str(eng.get("name", "")).isidentifier() \
                    or not isinstance(eng.get("argv"), list) or not eng["argv"] or not all(isinstance(a, str) for a in eng["argv"]):
                raise ConfigError("command engine needs name (identifier) and argv (non-empty list of strings)")
        elif eng != {"kind": "builtin"}:
            raise ConfigError('engine must be {"kind": "builtin"} or a command engine')
        seen_voters = set()
        for v in d.get("voters", []):
            if set(v) != {"actor", "vendor"} or not str(v["vendor"]).isidentifier() or v["vendor"] in ("human", "unknown"):
                raise ConfigError(f"voter {v} needs an exact actor id and a vendor name")
            validate_actor_id(v["actor"])
            if not v["actor"].startswith("agent:") or v["actor"] in seen_voters:
                raise ConfigError(f"voter {v['actor']} must be a unique agent:<name> id")
            seen_voters.add(v["actor"])
        cons = d.get("consensus", {"k": 2, "eligible": []})
        if set(cons) != {"k", "eligible"} or not (isinstance(cons["k"], int) and cons["k"] >= 2):
            raise ConfigError("consensus needs k (>= 2) and eligible")
        if bad := [e for e in cons["eligible"] if e in NEVER_CONSENSUS]:
            raise ConfigError(f"these findings always need a human and can't be consensus-eligible: {bad}")
        res = d.get("resolution", {})
        if not (0 < res.get("review_threshold_bp", 0) <= res.get("duplicate_threshold_bp", 0) <= 10000):
            raise ConfigError("resolution thresholds must satisfy 0 < review <= duplicate <= 10000")

    def actor(self, actor_id: str) -> Actor:
        validate_actor_id(actor_id)
        for rule in self.data["actors"]:
            if fnmatch.fnmatchcase(actor_id, rule["match"]):
                role = rule["role"]
                return Actor(actor_id, role, self.data["roles"][role]["trust"], self.vendor(actor_id))
        return Actor(actor_id, "observer", self.data["roles"].get("observer", {"trust": 0})["trust"], self.vendor(actor_id))

    def voters(self) -> dict[str, str]:
        return {v["actor"]: v["vendor"] for v in self.data.get("voters", [])}

    def vendor(self, actor_id: str) -> str:
        if actor_id in self.voters():
            return self.voters()[actor_id]
        for rule in self.data.get("vendors", []):
            if fnmatch.fnmatchcase(actor_id, rule["match"]):
                return rule["vendor"]
        return "unknown"

    def role(self, name: str) -> dict[str, Any]:
        return self.data["roles"][name]

    def digest(self) -> str:
        return digest(self.data)

    @classmethod
    def default(cls) -> Config:
        return cls(DEFAULT_CONFIG)
