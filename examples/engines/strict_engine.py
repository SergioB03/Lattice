#!/usr/bin/env python3
"""A deliberately different policy, speaking Lattice's command-engine protocol.

Reads a lattice.dev/policy-input/v1 document on stdin, writes a decision on stdout.
Use it to see portability metrics in action:

    lattice eval --with-engine strict="python examples/engines/strict_engine.py"

Policy: humans are trusted; agents may only write about themselves without review;
anything that closes a fact is denied for agents.
"""
import json
import sys

inp = json.load(sys.stdin)
actor = inp["actor"]
if inp["role"]["max_proposals_per_hour"] == 0:
    out = {"outcome": "deny", "rule_id": "strict.read_only", "reason": "Read-only role."}
elif actor["id"].startswith("human:"):
    out = {"outcome": "allow", "rule_id": "strict.human", "reason": "Humans are trusted."}
elif any(item["closes"] for item in inp["plan"]):
    out = {"outcome": "deny", "rule_id": "strict.no_agent_closes", "reason": "Agents may not close facts."}
elif all(item["target"] == actor["id"] or item["effect"] == "noop" for item in inp["plan"]):
    out = {"outcome": "allow", "rule_id": "strict.self_or_noop", "reason": "Self-scoped or already known."}
else:
    out = {"outcome": "review", "rule_id": "strict.shared_write", "reason": "Agent writes to shared entities need review."}
json.dump(out, sys.stdout)
