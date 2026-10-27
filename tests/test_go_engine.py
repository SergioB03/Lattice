"""Cross-language portability: the Go reference engine must agree with lattice-py on every eval case."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from lattice.core import Lattice
from lattice.evals import evaluate, load_suites
from lattice.policy import BuiltinEngine, CommandEngine

GO_DIR = Path(__file__).resolve().parents[1] / "examples" / "engines" / "go"
pytestmark = pytest.mark.skipif(shutil.which("go") is None, reason="Go toolchain not installed")


@pytest.fixture(scope="module")
def go_engine(tmp_path_factory):
    out = tmp_path_factory.mktemp("go") / ("lattice-go-engine" + (".exe" if sys.platform == "win32" else ""))
    subprocess.run(["go", "build", "-o", str(out), "."], cwd=GO_DIR, check=True, timeout=300)
    return CommandEngine("go", [str(out)])


def test_go_engine_matches_builtin_on_every_case(go_engine):
    rep = evaluate({"builtin": BuiltinEngine(), "go": go_engine}, load_suites([]))
    port = rep["portability"]["builtin~go"]
    assert port["kappa"] == 1.0, port["disagreements"]
    assert rep["engines"]["go"]["consistency"] == 1.0


def test_go_engine_decodes_strictly_and_lattice_fails_closed(go_engine):
    lat = Lattice.open(":memory:")
    lat.init(owner="human:sergio", insecure_dev=True)
    lat.propose("human:sergio", [{"op": "create_entity", "type": "project", "name": "Lattice"}])
    pid = lat.conn.execute("SELECT digest FROM decisions").fetchone()[0]
    inp = json.loads(lat.conn.execute("SELECT input FROM decisions WHERE digest=?", (pid,)).fetchone()[0])
    inp["surprise"] = "unknown field"
    d = go_engine.decide(inp)
    assert d["outcome"] == "deny" and d["rule_id"] == "engine.error" and "unknown field" in d["reason"]
