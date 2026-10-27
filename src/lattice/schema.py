"""The closed schema: registered entity types and predicates."""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass
from datetime import date
from importlib import resources
from typing import Any
from urllib.parse import urlparse

import yaml

from .canonical import digest

NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,39}$")
CARDINALITIES = ("one", "many")


class SchemaError(ValueError):
    pass


@dataclass(frozen=True)
class Predicate:
    name: str
    domain: tuple[str, ...] | str  # "*" or tuple of types
    range: tuple[str, ...] | str  # "*", tuple of types, or "literal:<kind>[:args]"
    cardinality: str
    description: str

    @property
    def is_literal(self) -> bool:
        return isinstance(self.range, str) and self.range.startswith("literal:")

    @property
    def literal_kind(self) -> str:
        return self.range.split(":")[1] if self.is_literal else ""

    def to_json(self) -> dict[str, Any]:
        return {
            "domain": list(self.domain) if isinstance(self.domain, tuple) else self.domain,
            "range": list(self.range) if isinstance(self.range, tuple) else self.range,
            "cardinality": self.cardinality,
            "description": self.description,
        }


def _types_field(value: Any, field: str, known: set[str]) -> tuple[str, ...] | str:
    if value == "*":
        return "*"
    if isinstance(value, str) and field == "range" and value.startswith("literal:"):
        kind = value.split(":")[1]
        if kind not in ("string", "url", "date", "integer", "enum"):
            raise SchemaError(f"unknown literal kind {kind!r}")
        if kind == "enum" and len(value.split(":", 2)) < 3:
            raise SchemaError("enum literal needs values, e.g. literal:enum:a,b,c")
        return value
    if not isinstance(value, list) or not value:
        raise SchemaError(f"{field} must be '*', a non-empty list of types, or a literal range")
    for t in value:
        if t not in known:
            raise SchemaError(f"{field} references unknown entity type {t!r}")
    return tuple(sorted(set(value)))


class Schema:
    def __init__(self, entity_types: dict[str, str], predicates: dict[str, dict[str, Any]]):
        self.entity_types: dict[str, str] = {}
        self.predicates: dict[str, Predicate] = {}
        for name, desc in entity_types.items():
            self._check_name(name)
            self.entity_types[name] = str(desc)
        for name, spec in predicates.items():
            self.add_predicate(name, spec)

    @staticmethod
    def _check_name(name: str) -> None:
        if not isinstance(name, str) or not NAME_RE.match(name):
            raise SchemaError(f"invalid name {name!r}: use lower_snake_case, 2-40 chars")

    def add_type(self, name: str, description: str) -> None:
        self._check_name(name)
        if name in self.entity_types:
            raise SchemaError(f"entity type {name!r} already exists")
        self.entity_types[name] = description

    def add_predicate(self, name: str, spec: dict[str, Any]) -> None:
        self._check_name(name)
        if name in self.predicates:
            raise SchemaError(f"predicate {name!r} already exists")
        if set(spec) - {"domain", "range", "cardinality", "description"}:
            raise SchemaError(f"predicate {name!r} has unknown fields {sorted(set(spec) - {'domain', 'range', 'cardinality', 'description'})}")
        card = spec.get("cardinality", "many")
        if card not in CARDINALITIES:
            raise SchemaError("cardinality must be 'one' or 'many'")
        known = set(self.entity_types)
        self.predicates[name] = Predicate(
            name,
            _types_field(spec.get("domain", "*"), "domain", known),
            _types_field(spec.get("range", "*"), "range", known),
            card,
            str(spec.get("description", "")),
        )

    # ---- lookups with helpful errors -------------------------------------------------

    def suggest(self, name: str, pool: list[str]) -> str:
        close = difflib.get_close_matches(name, pool, n=3, cutoff=0.5)
        return f" Did you mean: {', '.join(close)}?" if close else f" Known: {', '.join(sorted(pool))}."

    def require_type(self, name: str) -> None:
        if name not in self.entity_types:
            raise SchemaError(f"unknown entity type {name!r}." + self.suggest(name, list(self.entity_types)))

    def require_predicate(self, name: str) -> Predicate:
        p = self.predicates.get(name)
        if p is None:
            raise SchemaError(f"unknown predicate {name!r}." + self.suggest(name, list(self.predicates)))
        return p

    def check_domain(self, p: Predicate, subject_type: str) -> None:
        if p.domain != "*" and subject_type not in p.domain:
            raise SchemaError(f"{p.name!r} cannot have a {subject_type!r} subject; allowed: {', '.join(p.domain)}")

    def check_range_entity(self, p: Predicate, object_type: str) -> None:
        if p.is_literal:
            raise SchemaError(f"{p.name!r} takes a literal value, not an entity")
        if p.range != "*" and object_type not in p.range:
            raise SchemaError(f"{p.name!r} cannot point at a {object_type!r}; allowed: {', '.join(p.range)}")

    def check_literal(self, p: Predicate, value: Any) -> str:
        """Validate and normalise a literal. Returns its canonical string form."""
        if not p.is_literal:
            raise SchemaError(f"{p.name!r} points at an entity; pass 'object', not 'value'")
        kind = p.literal_kind
        if kind == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                raise SchemaError(f"{p.name!r} needs an integer")
            return str(value)
        if not isinstance(value, str) or not value.strip():
            raise SchemaError(f"{p.name!r} needs a non-empty string value")
        value = value.strip()
        if len(value) > 2000:
            raise SchemaError("literal values are limited to 2000 characters")
        if kind == "url":
            u = urlparse(value)
            if u.scheme not in ("http", "https") or not u.netloc:
                raise SchemaError(f"{p.name!r} needs an http(s) URL")
        elif kind == "date":
            try:
                date.fromisoformat(value)
            except ValueError as exc:
                raise SchemaError(f"{p.name!r} needs a YYYY-MM-DD date") from exc
        elif kind == "enum":
            allowed = p.range.split(":", 2)[2].split(",")
            if value not in allowed:
                raise SchemaError(f"{p.name!r} must be one of {', '.join(allowed)}")
        return value

    # ---- serialisation ------------------------------------------------------------------

    def to_json(self) -> dict[str, Any]:
        return {
            "entity_types": dict(sorted(self.entity_types.items())),
            "predicates": {k: self.predicates[k].to_json() for k in sorted(self.predicates)},
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Schema":
        return cls(data["entity_types"], data["predicates"])

    def digest(self) -> str:
        return digest(self.to_json())

    @classmethod
    def default(cls) -> "Schema":
        text = resources.files("lattice").joinpath("data/default_schema.yaml").read_text(encoding="utf-8")
        data = yaml.safe_load(text)
        return cls(data["entity_types"], data["predicates"])
