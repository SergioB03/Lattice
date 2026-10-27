"""A small demo graph that dogfoods Lattice: it describes Lattice, Skylr and the agents around them."""

from __future__ import annotations

from .core import Lattice


def seed(lat: Lattice, owner: str = "human:owner", passphrase: str | None = None) -> None:
    ops = [
        {"op": "create_entity", "type": "person", "name": "Sergio Banuelos", "aliases": ["Sergio"], "ref": "$me",
         "summary": "Builder. Owner of this graph."},
        {"op": "create_entity", "type": "project", "name": "Lattice", "ref": "$lattice",
         "summary": "Governed knowledge graph shared by humans and AI agents."},
        {"op": "create_entity", "type": "project", "name": "Skylr", "ref": "$skylr", "aliases": ["Skylar"],
         "summary": "AI engineering governance control plane. Agents propose; the control plane disposes."},
        {"op": "create_entity", "type": "agent", "name": "claude-code", "ref": "$cc", "aliases": ["Claude Code"],
         "summary": "Anthropic's coding agent."},
        {"op": "create_entity", "type": "agent", "name": "codex-rem", "ref": "$rem", "aliases": ["Rem", "Codex"],
         "summary": "OpenAI Codex agent, nicknamed Rem."},
        {"op": "create_entity", "type": "agent", "name": "ollama-qwen", "ref": "$qwen",
         "summary": "Local Qwen coder model served by Ollama on the home GPU."},
        {"op": "create_entity", "type": "tool", "name": "Neo4j", "ref": "$neo"},
        {"op": "create_entity", "type": "tool", "name": "SQLite", "ref": "$sqlite"},
        {"op": "create_entity", "type": "tool", "name": "Model Context Protocol", "aliases": ["MCP"], "ref": "$mcp"},
        {"op": "create_entity", "type": "concept", "name": "Agent governance", "ref": "$gov"},
        {"op": "create_entity", "type": "concept", "name": "Bitemporal facts", "ref": "$bt",
         "summary": "Track when something was true and when we learned it."},
        {"op": "create_entity", "type": "decision", "name": "SQLite is the source of truth; Neo4j is a projection",
         "ref": "$d1", "summary": "Embedded graph engines churn (Kùzu archived 2025); keep truth portable, rebuild projections."},
        {"op": "assert", "subject": "$me", "predicate": "owns", "object": "$lattice"},
        {"op": "assert", "subject": "$me", "predicate": "owns", "object": "$skylr"},
        {"op": "assert", "subject": "$me", "predicate": "works_on", "object": "$skylr"},
        {"op": "assert", "subject": "$me", "predicate": "works_on", "object": "$lattice"},
        {"op": "assert", "subject": "$lattice", "predicate": "status", "value": "active", "valid_from": "2026-10-27"},
        {"op": "assert", "subject": "$skylr", "predicate": "status", "value": "active", "valid_from": "2026-10-14"},
        {"op": "assert", "subject": "$lattice", "predicate": "uses", "object": "$sqlite"},
        {"op": "assert", "subject": "$lattice", "predicate": "uses", "object": "$mcp"},
        {"op": "assert", "subject": "$lattice", "predicate": "uses", "object": "$bt"},
        {"op": "assert", "subject": "$lattice", "predicate": "depends_on", "object": "$neo"},
        {"op": "assert", "subject": "$skylr", "predicate": "uses", "object": "$gov"},
        {"op": "assert", "subject": "$d1", "predicate": "about", "object": "$lattice"},
        {"op": "assert", "subject": "$d1", "predicate": "happened_on", "value": "2026-10-27"},
        {"op": "assert", "subject": "$cc", "predicate": "works_on", "object": "$lattice"},
        {"op": "assert", "subject": "$rem", "predicate": "works_on", "object": "$skylr"},
        {"op": "assert", "subject": "$qwen", "predicate": "works_on", "object": "$skylr"},
    ]
    lat.propose(owner, ops, "Demo seed", now="2026-10-27T12:00:00.000Z", passphrase=passphrase)
    # Agents write too, each attributed and governed.
    lat.propose("agent:claude-code", [
        {"op": "assert", "subject": "decision:sqlite-is-the-source-of-truth-neo4j-is-a-projection", "predicate": "decided_by",
         "object": "agent:claude-code", "source": "docs/decisions.md", "confidence": 95},
        {"op": "assert", "subject": "agent:claude-code", "predicate": "role", "value": "Lattice builder", "source": "observed"},
    ], "Record who made the storage call.", now="2026-10-27T12:05:00.000Z")
    lat.propose("agent:codex-rem", [
        {"op": "assert", "subject": "project:skylr", "predicate": "depends_on", "object": "tool:sqlite",
         "source": "Skylr go.mod (modernc.org/sqlite)", "confidence": 95},
    ], "Skylr's ledger is SQLite too.", now="2026-10-27T12:05:30.000Z")
    lat.propose("agent:ollama-qwen", [
        {"op": "assert", "subject": "project:lattice", "predicate": "uses", "object": "concept:agent-governance",
         "source": "docs/architecture.md", "confidence": 85},
    ], "Lattice is governed by a policy engine.", now="2026-10-27T12:05:40.000Z")
    lat.propose("agent:codex-rem", [
        {"op": "assert", "subject": "project:skylr", "predicate": "note", "source": "conversation", "confidence": 90,
         "value": "M1 offline foundations done: canonical hashing, CAS, SQLite ledger, typed policy, replay."},
    ], "Status from the Skylr thread.", now="2026-10-27T12:06:00.000Z")
    # Two proposals that land in the review queue, so the UI has something to show.
    lat.propose("agent:ollama-qwen", [
        {"op": "assert", "subject": "project:skylr", "predicate": "status", "value": "paused", "source": "guess", "confidence": 70},
    ], "Haven't seen commits today.", now="2026-10-27T12:07:00.000Z")
    lat.propose("agent:ollama-qwen", [
        {"op": "create_entity", "type": "project", "name": "Skyler", "summary": "Governance app"},
    ], "New project?", now="2026-10-27T12:08:00.000Z")
