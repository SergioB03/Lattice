"""Hash-chained, append-only event ledger.

The header layout matches Skylr's ``internal/ledger`` (seq, run_id, ts, type,
actor, payload_digest, prev_hash), and the event hash is the canonical digest
of that header. A ledger written by Lattice can therefore be verified by the
same rules Skylr applies to its own.

Like Skylr's ledger, this detects inconsistent edits. It does not authenticate
history against someone who controls the database file and can recompute every
hash.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_bytes, digest, raw_digest

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  seq INTEGER PRIMARY KEY,
  run_id TEXT NOT NULL,
  ts TEXT NOT NULL,
  type TEXT NOT NULL,
  actor TEXT NOT NULL,
  payload BLOB NOT NULL,
  payload_digest TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL UNIQUE
);
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
"""


@dataclass(frozen=True)
class Event:
    seq: int
    run_id: str
    ts: str
    type: str
    actor: str
    payload: dict[str, Any]
    payload_digest: str
    prev_hash: str
    hash: str

    def header(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "run_id": self.run_id,
            "ts": self.ts,
            "type": self.type,
            "actor": self.actor,
            "payload_digest": self.payload_digest,
            "prev_hash": self.prev_hash,
        }


class LedgerError(RuntimeError):
    pass


def append(conn: sqlite3.Connection, *, run_id: str, type: str, actor: str, payload: dict[str, Any], ts: str) -> Event:
    """Append inside the caller's transaction. The caller must hold a write lock."""
    if not (run_id and type and actor):
        raise LedgerError("empty event identity")
    body = canonical_bytes(payload)
    row = conn.execute("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
    seq, prev = (row[0] + 1, row[1]) if row else (1, "")
    header = {
        "seq": seq,
        "run_id": run_id,
        "ts": ts,
        "type": type,
        "actor": actor,
        "payload_digest": raw_digest(body),
        "prev_hash": prev,
    }
    h = digest(header)
    conn.execute(
        "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
        (seq, run_id, ts, type, actor, body, header["payload_digest"], prev, h),
    )
    return Event(seq, run_id, ts, type, actor, payload, header["payload_digest"], prev, h)


def iter_events(conn: sqlite3.Connection, after_seq: int = 0) -> Iterator[Event]:
    for r in conn.execute(
        "SELECT seq,run_id,ts,type,actor,payload,payload_digest,prev_hash,hash FROM events WHERE seq > ? ORDER BY seq",
        (after_seq,),
    ):
        yield Event(r[0], r[1], r[2], r[3], r[4], json.loads(bytes(r[5])), r[6], r[7], r[8])


def verify(conn: sqlite3.Connection) -> tuple[int, str]:
    """Walk the whole chain. Returns (count, head_hash) or raises LedgerError."""
    count, prev = 0, ""
    for r in conn.execute(
        "SELECT seq,run_id,ts,type,actor,payload,payload_digest,prev_hash,hash FROM events ORDER BY seq"
    ):
        seq, run_id, ts, typ, actor, body, pd, ph, h = r
        header = {"seq": seq, "run_id": run_id, "ts": ts, "type": typ, "actor": actor, "payload_digest": pd, "prev_hash": ph}
        if seq != count + 1 or ph != prev or raw_digest(bytes(body)) != pd or digest(header) != h:
            raise LedgerError(f"ledger mismatch at sequence {seq}")
        count, prev = count + 1, h
    return count, prev
