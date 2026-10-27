"""Project the Lattice ledger into Neo4j, for Browser/Bloom exploration, Cypher and GDS.

Neo4j is a *projection*: it only ever receives effects that already passed
governance and were committed to the ledger. Sync is incremental and exactly-once:
each ledger event is applied in one Neo4j transaction that also advances a
watermark node, ``(:LatticeMeta {key:'ledger'})``, holding the last applied
``seq`` and its hash. If the watermark hash doesn't match our ledger at that seq,
the projection came from a different ledger, and sync refuses unless asked to rebuild.

Mapping:
  entity           (:Entity:<Type> {id, name, type, summary, aliases})
  entity → entity  (s)-[:<PREDICATE> {fact_id, status, valid_from, valid_to, actor, trust, confidence_bp}]->(o)
  literal          (s)-[:<PREDICATE> {...}]->(:Value {fact_id, value})
"""

from __future__ import annotations

import os
import re
from typing import Any

from . import ledger
from .core import Lattice, LatticeError

IDENT = re.compile(r"^[a-z][a-z0-9_]{1,39}$")


def rel_type(predicate: str) -> str:
    if not IDENT.match(predicate):
        raise LatticeError(f"refusing to interpolate unsafe predicate {predicate!r}")
    return predicate.upper()


def label(entity_type: str) -> str:
    if not IDENT.match(entity_type):
        raise LatticeError(f"refusing to interpolate unsafe type {entity_type!r}")
    return "".join(part.capitalize() for part in entity_type.split("_"))


def statements_for(effect: dict[str, Any], seq: int, predicate_of) -> list[tuple[str, dict[str, Any]]]:
    k = effect["effect"]
    if k == "entity_created":
        return [((f"MERGE (e:Entity {{id:$id}}) SET e:{label(effect['type'])}, e.name=$name, e.type=$type, "
                  "e.summary=$summary, e.aliases=$aliases, e.created_seq=$seq"),
                 {"id": effect["id"], "name": effect["name"], "type": effect["type"], "summary": effect["summary"],
                  "aliases": effect["aliases"], "seq": seq})]
    if k == "alias_added":
        return [(("MATCH (e:Entity {id:$id}) SET e.aliases = CASE WHEN $alias IN coalesce(e.aliases, []) "
                  "THEN e.aliases ELSE coalesce(e.aliases, []) + $alias END"), {"id": effect["entity"], "alias": effect["alias"]})]
    if k == "summary_updated":
        return [("MATCH (e:Entity {id:$id}) SET e.summary=$summary", {"id": effect["entity"], "summary": effect["summary"]})]
    if k == "fact_inserted":
        f = effect["fact"]
        props = {key: f[key] for key in ("status", "valid_from", "valid_to", "actor", "trust", "confidence_bp", "source", "proposal_id")}
        props["recorded_seq"] = seq
        rt = rel_type(f["predicate"])
        if f["object"]:
            return [(f"MATCH (s:Entity {{id:$s}}), (o:Entity {{id:$o}}) MERGE (s)-[r:{rt} {{fact_id:$fid}}]->(o) SET r += $props",
                     {"s": f["subject"], "o": f["object"], "fid": f["id"], "props": props})]
        return [((f"MATCH (s:Entity {{id:$s}}) MERGE (v:Value {{fact_id:$fid}}) SET v.value=$value, v.predicate=$pred "
                  f"MERGE (s)-[r:{rt} {{fact_id:$fid}}]->(v) SET r += $props"),
                 {"s": f["subject"], "fid": f["id"], "value": f["value"], "pred": f["predicate"], "props": props})]
    if k == "fact_closed":
        rt = rel_type(predicate_of(effect["id"]))
        return [((f"MATCH ()-[r:{rt} {{fact_id:$fid}}]->() SET r.status=$status, r.valid_to=$valid_to, r.closed_seq=$seq, "
                  "r.close_reason=$reason"), {"fid": effect["id"], "status": effect["status"], "valid_to": effect["valid_to"],
                                            "seq": seq, "reason": effect["reason"]})]
    return []  # schema effects live in Lattice, not in the projection


def sync(lat: Lattice, driver, database: str | None = None, rebuild: bool = False) -> dict[str, Any]:
    predicate_of = lambda fid: lat.conn.execute("SELECT predicate FROM facts WHERE id=?", (fid,)).fetchone()[0]
    with driver.session(database=database) as session:
        session.run("CREATE CONSTRAINT lattice_entity_id IF NOT EXISTS FOR (e:Entity) REQUIRE e.id IS UNIQUE").consume()
        session.run("CREATE CONSTRAINT lattice_value_fact IF NOT EXISTS FOR (v:Value) REQUIRE v.fact_id IS UNIQUE").consume()
        if rebuild:
            session.run("MATCH (n) WHERE n:Entity OR n:Value OR n:LatticeMeta DETACH DELETE n").consume()
        rec = session.run("MATCH (m:LatticeMeta {key:'ledger'}) RETURN m.seq AS seq, m.head AS head").single()
        start, head = (int(rec["seq"]), rec["head"]) if rec else (0, "")
        if start:
            row = lat.conn.execute("SELECT hash FROM events WHERE seq=?", (start,)).fetchone()
            if not row or row[0] != head:
                raise LatticeError("Neo4j projection was built from a different ledger; run `lattice neo4j sync --rebuild`")
        applied = events = 0
        for ev in ledger.iter_events(lat.conn, after_seq=start):
            stmts = []
            if ev.type == "proposal.applied":
                for eff in ev.payload["effects"]:
                    stmts += statements_for(eff, ev.seq, predicate_of)

            def work(tx, stmts=stmts, ev=ev):
                for q, params in stmts:
                    tx.run(q, **params).consume()
                tx.run("MERGE (m:LatticeMeta {key:'ledger'}) SET m.seq=$seq, m.head=$head", seq=ev.seq, head=ev.hash).consume()

            session.execute_write(work)
            events += 1
            applied += len(stmts)
    return {"events_projected": events, "statements": applied, "from_seq": start, "to_seq": lat.head()[0]}


def sync_from_env(lat: Lattice, rebuild: bool = False) -> dict[str, Any]:
    try:
        from neo4j import GraphDatabase
    except ImportError as exc:
        raise LatticeError("install the Neo4j driver: pip install 'lattice-kg[neo4j]'") from exc
    uri = os.environ.get("LATTICE_NEO4J_URI", "bolt://localhost:7687")
    auth = (os.environ.get("LATTICE_NEO4J_USER", "neo4j"), os.environ.get("LATTICE_NEO4J_PASSWORD", "lattice-dev-only"))
    with GraphDatabase.driver(uri, auth=auth) as driver:
        driver.verify_connectivity()
        return sync(lat, driver, database=os.environ.get("LATTICE_NEO4J_DATABASE") or None, rebuild=rebuild)
