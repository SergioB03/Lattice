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
OPS = ("create_entity", "assert", "retract", "add_alias", "update_summary", "define_type", "define_predicate")
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
}


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Actor:
    id: str
    role: str
    trust: int

    def to_json(self) -> dict[str, Any]:
        return {"id": self.id, "role": self.role, "trust": self.trust}


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
        res = d.get("resolution", {})
        if not (0 < res.get("review_threshold_bp", 0) <= res.get("duplicate_threshold_bp", 0) <= 10000):
            raise ConfigError("resolution thresholds must satisfy 0 < review <= duplicate <= 10000")

    def actor(self, actor_id: str) -> Actor:
        validate_actor_id(actor_id)
        for rule in self.data["actors"]:
            if fnmatch.fnmatchcase(actor_id, rule["match"]):
                role = rule["role"]
                return Actor(actor_id, role, self.data["roles"][role]["trust"])
        return Actor(actor_id, "observer", self.data["roles"].get("observer", {"trust": 0})["trust"])

    def role(self, name: str) -> dict[str, Any]:
        return self.data["roles"][name]

    def digest(self) -> str:
        return digest(self.data)

    @classmethod
    def default(cls) -> Config:
        return cls(DEFAULT_CONFIG)
