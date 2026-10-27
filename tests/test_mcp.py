"""End-to-end: launch `lattice-mcp` over stdio exactly like Claude Code / Codex would."""

import asyncio
import json
import sys

import pytest

pytest.importorskip("mcp")
from mcp import Client, StdioServerParameters

from lattice.core import Lattice
from lattice.demo import seed


def _text(res) -> str:
    return "".join(getattr(c, "text", "") for c in res.content)


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "g.db"
    lat = Lattice.open(path)
    lat.init(owner="human:sergio")
    seed(lat, "human:sergio")
    lat.close()
    return str(path)


def test_stdio_roundtrip(db):
    params = StdioServerParameters(command=sys.executable, args=["-m", "lattice.mcp_server", "--db", db],
                                   env={"LATTICE_ACTOR": "agent:claude-code"})

    async def run():
        async with Client(params) as client:
            tools = {t.name for t in (await client.list_tools()).tools}
            assert {"lattice_propose", "lattice_context", "lattice_search", "lattice_schema"} <= tools
            assert not any("approve" in t or "cypher" in t or "delete" in t for t in tools)

            who = json.loads(_text(await client.call_tool("lattice_whoami", {})))
            assert who["actor"] == "agent:claude-code" and who["role"] == "agent"
            assert who["own_entity"] == "agent:claude-code"

            hits = _text(await client.call_tool("lattice_search", {"query": "skylar"}))
            assert "project:skylr" in hits

            ctx = _text(await client.call_tool("lattice_context", {"entity": "project:skylr", "budget_tokens": 200}))
            assert "«" in ctx and "omitted" in ctx

            res = json.loads(_text(await client.call_tool("lattice_propose", {
                "ops": [{"op": "assert", "subject": "project:lattice", "predicate": "note",
                         "value": "MCP round trip works", "source": "tests/test_mcp.py", "confidence": 0.9}],
                "justification": "e2e test", "idempotency_key": "t1"})))
            assert res["status"] == "applied", res
            again = json.loads(_text(await client.call_tool("lattice_propose", {
                "ops": [{"op": "assert", "subject": "project:lattice", "predicate": "note",
                         "value": "MCP round trip works", "source": "tests/test_mcp.py", "confidence": 0.9}],
                "justification": "e2e test", "idempotency_key": "t1"})))
            assert again["proposal_id"] == res["proposal_id"] and again["deduplicated"]

    asyncio.run(run())


def test_refuses_human_actor(db):
    import subprocess
    r = subprocess.run([sys.executable, "-m", "lattice.mcp_server", "--db", db, "--actor", "human:sergio"],
                       capture_output=True, text=True, timeout=30, check=False)
    assert r.returncode == 2 and "refusing" in r.stderr
