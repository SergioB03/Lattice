"""Neo4j projection tests.

The fake-driver tests always run. The live test runs when LATTICE_TEST_NEO4J_URI is set
(CI starts a neo4j:5-community service container for it).
"""

import os

import pytest

from lattice.core import Lattice, LatticeError
from lattice.demo import seed
from lattice.neo4j_sync import rel_type, sync


class _Res:
    def __init__(self, rec=None):
        self.rec = rec

    def consume(self):
        return None

    def single(self):
        return self.rec


class FakeSession:
    def __init__(self, store):
        self.store = store

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, q, **params):
        self.store["queries"].append(q)
        if "DETACH DELETE" in q:
            self.store.pop("meta", None)
        if q.startswith("MATCH (m:LatticeMeta"):
            return _Res(self.store.get("meta"))
        if q.startswith("MERGE (m:LatticeMeta"):
            self.store["meta"] = {"seq": params["seq"], "head": params["head"]}
        return _Res()

    def execute_write(self, fn):
        fn(self)


class FakeDriver:
    def __init__(self):
        self.store = {"queries": []}

    def session(self, database=None):
        return FakeSession(self.store)


@pytest.fixture()
def lat():
    lat = Lattice.open(":memory:")
    lat.init(owner="human:sergio")
    seed(lat, "human:sergio")
    return lat


def test_identifiers_are_never_injected():
    assert rel_type("works_on") == "WORKS_ON"
    with pytest.raises(LatticeError):
        rel_type("x}]->() DETACH DELETE n //")


def test_incremental_exactly_once_with_watermark(lat):
    d = FakeDriver()
    first = sync(lat, d)
    assert first["from_seq"] == 0 and first["statements"] > 0
    assert d.store["meta"]["seq"] == lat.head()[0]
    assert any("MERGE (e:Entity" in q and "SET e:Project" in q for q in d.store["queries"])
    assert any("[r:WORKS_ON {fact_id:$fid}]" in q for q in d.store["queries"])
    again = sync(lat, d)
    assert again["events_projected"] == 0
    lat.propose("human:sergio", [{"op": "assert", "subject": "Skylr", "predicate": "status", "value": "paused"}])
    third = sync(lat, d)
    assert third["events_projected"] == 3
    assert any("SET r.status=$status" in q for q in d.store["queries"])  # the superseded fact is closed in Neo4j


def test_refuses_foreign_projection(lat):
    d = FakeDriver()
    d.store["meta"] = {"seq": 3, "head": "sha256:" + "0" * 64}
    with pytest.raises(LatticeError):
        sync(lat, d)
    assert sync(lat, d, rebuild=True)["to_seq"] == lat.head()[0]


@pytest.mark.neo4j
@pytest.mark.skipif(not os.environ.get("LATTICE_TEST_NEO4J_URI"), reason="no live Neo4j")
def test_live_neo4j_projection(lat):
    from neo4j import GraphDatabase

    uri = os.environ["LATTICE_TEST_NEO4J_URI"]
    auth = ("neo4j", os.environ.get("LATTICE_TEST_NEO4J_PASSWORD", "lattice-dev-only"))
    with GraphDatabase.driver(uri, auth=auth) as driver:
        sync(lat, driver, rebuild=True)
        with driver.session() as s:
            n = s.run("MATCH (e:Entity) RETURN count(e) AS n").single()["n"]
            assert n == lat.stats()["entities"]
            row = s.run("MATCH (:Person {id:'person:sergio-banuelos'})-[r:WORKS_ON]->(p:Project) "
                        "WHERE r.status='current' RETURN collect(p.id) AS ps").single()
            assert set(row["ps"]) == {"project:skylr", "project:lattice"}
        lat.propose("human:sergio", [{"op": "assert", "subject": "Skylr", "predicate": "status", "value": "done"}])
        sync(lat, driver)
        with driver.session() as s:
            rows = s.run("MATCH (:Project {id:'project:skylr'})-[r:STATUS]->(v:Value) RETURN v.value AS v, r.status AS st "
                         "ORDER BY r.recorded_seq").data()
            assert [(r["v"], r["st"]) for r in rows] == [("active", "superseded"), ("done", "current")]
