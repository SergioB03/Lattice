"""Canonical JSON and digests, compatible with Skylr's identity package.

Lattice hashes the same restricted JSON subset Skylr does: objects, arrays,
strings, booleans and safe integers. For that subset, sorted-key compact JSON
is byte-identical to RFC 8785 (JCS) as long as keys sort the same under
UTF-16 code units and code points. Keys are therefore restricted to the Basic
Multilingual Plane. Floats and nulls are rejected rather than silently
normalised, so a digest can never depend on float formatting.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

MAX_SAFE_INT = 2**53 - 1
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


class CanonicalError(ValueError):
    """Raised when a value is outside the hashable JSON subset."""


def _check(value: Any, path: str) -> None:
    if value is None:
        raise CanonicalError(f"{path}: null is not allowed")
    if isinstance(value, bool) or isinstance(value, str):
        return
    if isinstance(value, int):
        if not -MAX_SAFE_INT <= value <= MAX_SAFE_INT:
            raise CanonicalError(f"{path}: integer outside the safe range")
        return
    if isinstance(value, float):
        raise CanonicalError(f"{path}: floats are not allowed; use integers or decimal strings")
    if isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            _check(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalError(f"{path}: object keys must be strings")
            if any(ord(ch) > 0xFFFF for ch in key):
                raise CanonicalError(f"{path}: object keys must be in the Basic Multilingual Plane")
            _check(item, f"{path}.{key}")
        return
    raise CanonicalError(f"{path}: unsupported type {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    """Return the canonical UTF-8 encoding of ``value``."""
    _check(value, "$")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def raw_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest(value: Any) -> str:
    """SHA-256 over canonical JSON, formatted like Skylr: ``sha256:<hex>``."""
    return raw_digest(canonical_bytes(value))


def format_ts(moment: datetime) -> str:
    """UTC timestamp with exactly millisecond precision."""
    if moment.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def parse_ts(text: str) -> datetime:
    if not isinstance(text, str) or not TS_RE.match(text):
        raise ValueError(f"timestamp must look like 2026-10-27T15:04:05.000Z, got {text!r}")
    return datetime.strptime(text, TS_FORMAT).replace(tzinfo=timezone.utc)


def now_ts() -> str:
    return format_ts(datetime.now(timezone.utc))
