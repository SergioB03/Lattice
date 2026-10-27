"""SQLite storage: tables, effect application and rebuild-from-ledger.

The graph tables are a materialised view of the ledger. ``apply_event`` is the
only code that mutates them, and ``rebuild`` replays a ledger into a fresh
database and must reproduce the same rows. Tests check that.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from . import ledger
from .text import norm_key

DDL = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS entities(
  id TEXT PRIMARY KEY, type TEXT NOT NULL, name TEXT NOT NULL, name_key TEXT NOT NULL,
  summary TEXT NOT NULL, created_seq INTEGER NOT NULL, created_by TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS entities_name_key ON entities(name_key);
CREATE TABLE IF NOT EXISTS aliases(
  entity_id TEXT NOT NULL REFERENCES entities(id), alias TEXT NOT NULL, alias_key TEXT NOT NULL,
  added_seq INTEGER NOT NULL, added_by TEXT NOT NULL, PRIMARY KEY(entity_id, alias_key));
CREATE INDEX IF NOT EXISTS aliases_key ON aliases(alias_key);
CREATE TABLE IF NOT EXISTS facts(
  id TEXT PRIMARY KEY, subject TEXT NOT NULL REFERENCES entities(id), predicate TEXT NOT NULL,
  object TEXT NOT NULL, value TEXT NOT NULL, valid_from TEXT NOT NULL, valid_to TEXT NOT NULL,
  status TEXT NOT NULL, confidence_bp INTEGER NOT NULL, actor TEXT NOT NULL, trust INTEGER NOT NULL,
  source TEXT NOT NULL, evidence TEXT NOT NULL, proposal_id TEXT NOT NULL,
  recorded_seq INTEGER NOT NULL, recorded_at TEXT NOT NULL, closed_seq INTEGER NOT NULL, close_reason TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS facts_sp ON facts(subject, predicate, status);
CREATE INDEX IF NOT EXISTS facts_obj ON facts(object, status);
CREATE TABLE IF NOT EXISTS proposals(
  id TEXT PRIMARY KEY, content_digest TEXT NOT NULL, actor TEXT NOT NULL, idempotency_key TEXT NOT NULL,
  body TEXT NOT NULL, status TEXT NOT NULL, received_at TEXT NOT NULL, received_seq INTEGER NOT NULL,
  decision_digest TEXT NOT NULL, detail TEXT NOT NULL, updated_seq INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS proposals_status ON proposals(status);
CREATE INDEX IF NOT EXISTS proposals_actor ON proposals(actor, received_at);
CREATE TABLE IF NOT EXISTS decisions(
  digest TEXT PRIMARY KEY, proposal_id TEXT NOT NULL, input_digest TEXT NOT NULL,
  body TEXT NOT NULL, input TEXT NOT NULL, seq INTEGER NOT NULL);
CREATE VIRTUAL TABLE IF NOT EXISTS entity_fts USING fts5(entity_id UNINDEXED, text, tokenize='trigram');
"""

GRAPH_TABLES = ("entities", "aliases", "facts", "proposals", "decisions")


def connect(path: str | Path) -> sqlite3.Connection:
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), isolation_level=None, timeout=10, check_same_thread=False)
    conn.execute("PRAGMA busy_timeout=10000")
    if str(path) != ":memory:":
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    conn.executescript(ledger.SCHEMA)
    conn.executescript(DDL)
    return conn


def get_meta(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


def _reindex(conn: sqlite3.Connection, entity_id: str) -> None:
    row = conn.execute("SELECT name, summary FROM entities WHERE id=?", (entity_id,)).fetchone()
    if not row:
        return
    aliases = [r[0] for r in conn.execute("SELECT alias FROM aliases WHERE entity_id=? ORDER BY alias_key", (entity_id,))]
    text = " | ".join([row[0], *aliases, entity_id, row[1]])
    conn.execute("DELETE FROM entity_fts WHERE entity_id=?", (entity_id,))
    conn.execute("INSERT INTO entity_fts(entity_id, text) VALUES(?,?)", (entity_id, text))


def apply_effects(conn: sqlite3.Connection, effects: Iterable[dict[str, Any]], *, seq: int, ts: str, actor: str) -> None:
    for e in effects:
        kind = e["effect"]
        if kind == "entity_created":
            conn.execute(
                "INSERT INTO entities VALUES(?,?,?,?,?,?,?)",
                (e["id"], e["type"], e["name"], norm_key(e["name"]), e["summary"], seq, actor),
            )
            for alias in e["aliases"]:
                conn.execute(
                    "INSERT OR IGNORE INTO aliases VALUES(?,?,?,?,?)", (e["id"], alias, norm_key(alias), seq, actor)
                )
            _reindex(conn, e["id"])
        elif kind == "alias_added":
            conn.execute(
                "INSERT OR IGNORE INTO aliases VALUES(?,?,?,?,?)", (e["entity"], e["alias"], norm_key(e["alias"]), seq, actor)
            )
            _reindex(conn, e["entity"])
        elif kind == "summary_updated":
            conn.execute("UPDATE entities SET summary=? WHERE id=?", (e["summary"], e["entity"]))
            _reindex(conn, e["entity"])
        elif kind == "fact_inserted":
            f = e["fact"]
            conn.execute(
                "INSERT INTO facts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    f["id"], f["subject"], f["predicate"], f["object"], f["value"], f["valid_from"], f["valid_to"],
                    f["status"], f["confidence_bp"], f["actor"], f["trust"], f["source"], f["evidence"],
                    f["proposal_id"], seq, ts, 0, "",
                ),
            )
        elif kind == "fact_closed":
            cur = conn.execute(
                "UPDATE facts SET status=?, valid_to=?, closed_seq=?, close_reason=? WHERE id=? AND status='current'",
                (e["status"], e["valid_to"], seq, e["reason"], e["id"]),
            )
            if cur.rowcount != 1:
                raise RuntimeError(f"fact {e['id']} is not current; refusing to close it twice")
        elif kind == "type_defined":
            schema = json.loads(get_meta(conn, "schema"))
            schema["entity_types"][e["name"]] = e["description"]
            set_meta(conn, "schema", json.dumps(schema, sort_keys=True))
        elif kind == "predicate_defined":
            schema = json.loads(get_meta(conn, "schema"))
            schema["predicates"][e["name"]] = e["spec"]
            set_meta(conn, "schema", json.dumps(schema, sort_keys=True))
        else:
            raise RuntimeError(f"unknown effect {kind!r}")


def apply_event(conn: sqlite3.Connection, ev: ledger.Event) -> None:
    """Materialise one ledger event into the graph tables."""
    p = ev.payload
    if ev.type == "lattice.initialized":
        set_meta(conn, "schema", json.dumps(p["schema"], sort_keys=True))
        set_meta(conn, "config", json.dumps(p["config"], sort_keys=True))
        set_meta(conn, "initialized_at", ev.ts)
    elif ev.type == "config.changed":
        set_meta(conn, "config", json.dumps(p["config"], sort_keys=True))
    elif ev.type == "owner.passphrase_set":
        set_meta(conn, "owner_hash", p["scrypt"])
    elif ev.type == "proposal.received":
        conn.execute(
            "INSERT INTO proposals VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                p["id"], p["content_digest"], p["proposal"]["actor"], p["proposal"]["idempotency_key"],
                json.dumps(p["proposal"], sort_keys=True), "received", ev.ts, ev.seq, "", "", ev.seq,
            ),
        )
    elif ev.type == "proposal.invalid":
        conn.execute(
            "UPDATE proposals SET status='invalid', detail=?, updated_seq=? WHERE id=?",
            (json.dumps(p["errors"], sort_keys=True), ev.seq, p["id"]),
        )
    elif ev.type == "decision.recorded":
        d = p["decision"]
        conn.execute(
            "INSERT INTO decisions VALUES(?,?,?,?,?,?)",
            (p["decision_digest"], p["proposal_id"], d["input_digest"], json.dumps(d, sort_keys=True),
             json.dumps(p["input"], sort_keys=True), ev.seq),
        )
        status = {"allow": "allowed", "review": "pending", "deny": "denied"}[d["outcome"]]
        conn.execute(
            "UPDATE proposals SET status=?, decision_digest=?, detail=?, updated_seq=? WHERE id=?",
            (status, p["decision_digest"], json.dumps({"rule_id": d["rule_id"], "reason": d["reason"]}, sort_keys=True), ev.seq,
             p["proposal_id"]),
        )
    elif ev.type == "proposal.applied":
        apply_effects(conn, p["effects"], seq=ev.seq, ts=ev.ts, actor=p["actor"])
        conn.execute("UPDATE proposals SET status='applied', updated_seq=? WHERE id=?", (ev.seq, p["proposal_id"]))
    elif ev.type == "proposal.rejected":
        conn.execute(
            "UPDATE proposals SET status='rejected', detail=?, updated_seq=? WHERE id=?",
            (json.dumps({"by": ev.actor, "reason": p["reason"]}, sort_keys=True), ev.seq, p["proposal_id"]),
        )
    elif ev.type == "ledger.anchored":
        pass
    else:
        raise RuntimeError(f"unknown ledger event type {ev.type!r}")


def append_and_apply(conn: sqlite3.Connection, *, run_id: str, type: str, actor: str, payload: dict[str, Any], ts: str) -> ledger.Event:
    ev = ledger.append(conn, run_id=run_id, type=type, actor=actor, payload=payload, ts=ts)
    apply_event(conn, ev)
    return ev


def dump_tables(conn: sqlite3.Connection) -> dict[str, list[tuple]]:
    out = {t: sorted(conn.execute(f"SELECT * FROM {t}").fetchall()) for t in GRAPH_TABLES}
    out["meta"] = sorted(r for r in conn.execute("SELECT * FROM meta") if r[0] != "neo4j_watermark")
    return out


def rebuild(source: sqlite3.Connection) -> sqlite3.Connection:
    """Replay ``source``'s ledger into a fresh in-memory database."""
    ledger.verify(source)
    fresh = connect(":memory:")
    fresh.execute("BEGIN IMMEDIATE")
    for ev in ledger.iter_events(source):
        body = json.dumps(ev.payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        fresh.execute(
            "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
            (ev.seq, ev.run_id, ev.ts, ev.type, ev.actor, body, ev.payload_digest, ev.prev_hash, ev.hash),
        )
        apply_event(fresh, ev)
    fresh.execute("COMMIT")
    ledger.verify(fresh)
    return fresh
