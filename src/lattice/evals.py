"""Governance evals: run scenario suites against policy engines and measure neutrality.

Metrics (see docs/evals.md for the reasoning and how each one resists gaming):

* coverage     share of cases that got a well-formed decision (crashes/timeouts count against)
* correctness  confusion matrix vs. expectations; false allows are weighted 3x
* parity       metamorphic: swap the agent vendor (same role), NFD-normalise text → outcome must not change
* consistency  same input decided twice + full ledger rebuild/replay → byte-identical decisions
* portability  Cohen's kappa between engines, plus allow/not-allow agreement and a list of disagreements
* latency      p50 / p99 per engine
* review_rate  reported so "review everything" can't hide behind perfect parity/portability
"""

from __future__ import annotations

import copy
import json
import shlex
import statistics
import unicodedata
from collections import Counter
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from . import store
from .canonical import digest
from .core import Lattice
from .demo import seed
from .policy import BuiltinEngine, CommandEngine, Engine

OUTCOMES = ("allow", "review", "deny", "invalid")
VENDORS = ["agent:claude-code", "agent:codex-rem", "agent:ollama-qwen", "agent:antigravity", "agent:replit"]
OWNER = "human:sergio"
CASE_NOW = "2026-10-28T09:00:00.000Z"


def load_suites(paths: list[str]) -> list[dict[str, Any]]:
    if not paths:
        root = resources.files("lattice").joinpath("data/scenarios")
        return [yaml.safe_load(p.read_text(encoding="utf-8")) for p in sorted(root.iterdir(), key=lambda p: p.name)
                if p.name.endswith(".yaml")]
    return [yaml.safe_load(Path(p).read_text(encoding="utf-8")) for p in paths]


def _fresh(engine: Engine) -> Lattice:
    lat = Lattice.open(":memory:", engine=BuiltinEngine())
    lat.init(owner=OWNER, insecure_dev=True, now="2026-10-27T11:00:00.000Z")  # evals never touch real secrets
    seed(lat, OWNER)
    lat.engine = engine
    return lat


def _outcome(res: dict[str, Any]) -> str:
    return {"applied": "allow", "allowed": "allow", "pending": "review", "denied": "deny", "invalid": "invalid",
            "rejected": "deny"}[res["status"]]


def run_case(engine: Engine, case: dict[str, Any], actor: str | None = None, mutate=None) -> dict[str, Any]:
    lat = _fresh(engine)
    prelude_ids: list[str] = []
    for i, pre in enumerate(case.get("prelude", [])):
        pre_ops = _bind_prelude(prelude_ids, copy.deepcopy(pre["ops"]), lat)
        r = lat.propose(pre["actor"], pre_ops, pre.get("justification", ""), now=f"2026-10-28T08:{i % 60:02d}:00.000Z")
        prelude_ids.append(r["proposal_id"])
    ops = _bind_prelude(prelude_ids, _bind_facts(lat, copy.deepcopy(case["ops"])), lat)
    if mutate:
        ops = mutate(ops)
    import time
    t0 = time.perf_counter()
    try:
        res = lat.propose(actor or case["actor"], ops, case.get("justification", ""), now=CASE_NOW)
        ok = True
    except Exception as exc:  # noqa: BLE001
        res, ok = {"status": "error", "outcome": "error", "rule_id": "harness.error", "reason": str(exc)}, False
    ms = (time.perf_counter() - t0) * 1000
    outcome = _outcome(res) if ok else "error"
    if ok and case.get("then_status"):
        idx, want = case["then_status"]
        got = lat.proposal_status(prelude_ids[idx])["status"]
        if got != want:  # the case's follow-on effect didn't happen: report it as its own outcome
            outcome = f"{outcome}/then:{got}"
    out = {"outcome": outcome, "rule_id": res.get("rule_id", ""), "ms": ms,
           "decision_digest": res.get("decision_digest", ""), "lat": lat}
    return out


def _bind_prelude(ids: list[str], ops: list[dict[str, Any]], lat: Lattice) -> list[dict[str, Any]]:
    """Replace "$prelude:N" with the N-th prelude proposal's id, and "$plan:N" with the plan digest a voter
    would currently see for it (what lattice_review_queue shows)."""
    for op in ops:
        for k, v in list(op.items()):
            if isinstance(v, str) and v.startswith("$prelude:"):
                op[k] = ids[int(v.split(":")[1])]
            elif isinstance(v, str) and v.startswith("$plan:"):
                pid = ids[int(v.split(":")[1])]
                op[k] = next((p["plan_digest"] for p in lat.list_proposals("pending", limit=200) if p["proposal_id"] == pid), "")
    return ops


def _bind_facts(lat: Lattice, ops: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Replace "$fact:<entity>:<predicate>" with the current fact id, so suites stay readable."""
    for op in ops:
        for k, v in list(op.items()):
            if isinstance(v, str) and v.startswith("$fact:"):
                ent, _, pred = v[len("$fact:"):].rpartition(":")
                hits = [f["id"] for f in lat.facts(ent) if f["predicate"] == pred]
                op[k] = hits[0] if hits else v
    return ops


def _nfd(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFD", value)
    if isinstance(value, list):
        return [_nfd(v) for v in value]
    if isinstance(value, dict):
        return {k: (v if k in ("op", "predicate", "type") else _nfd(v)) for k, v in value.items()}
    return value


def kappa(a: list[str], b: list[str]) -> float:
    n = len(a)
    if n == 0:
        return 1.0
    po = sum(x == y for x, y in zip(a, b)) / n
    ca, cb = Counter(a), Counter(b)
    pe = sum(ca[k] * cb[k] for k in set(a) | set(b)) / (n * n)
    return 1.0 if pe == 1 else round((po - pe) / (1 - pe), 4)


def pct(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    v = sorted(values)
    return round(v[min(len(v) - 1, round(q * (len(v) - 1)))], 2)


def evaluate(engines: dict[str, Engine], suites: list[dict[str, Any]]) -> dict[str, Any]:
    cases = [c | {"suite": s["name"]} for s in suites for c in s["cases"]]
    report: dict[str, Any] = {"cases": len(cases), "suites": [s["name"] for s in suites], "engines": {}}
    outcomes_by_engine: dict[str, list[str]] = {}
    for name, eng in engines.items():
        rows, lat_ms, parity_checks, parity_fail, consist_checks, consist_fail = [], [], 0, [], 0, []
        for c in cases:
            r = run_case(eng, c)
            lat_ms.append(r["ms"])
            rows.append({"id": c["id"], "suite": c["suite"], "category": c.get("category", ""), "expect": c["expect"],
                         "got": r["outcome"], "rule_id": r["rule_id"], "adversarial": bool(c.get("adversarial")),
                         "known_gap": bool(c.get("known_gap"))})
            # consistency: re-decide the exact recorded input, then rebuild the whole db from its ledger and replay
            if r["decision_digest"]:
                consist_checks += 1
                lat: Lattice = r["lat"]
                inp = json.loads(lat.conn.execute("SELECT input FROM decisions WHERE digest=?", (r["decision_digest"],)).fetchone()[0])
                same_twice = digest(eng.decide(inp)) == r["decision_digest"]
                rebuilt = Lattice(store.rebuild(lat.conn), engine=eng)
                replay_ok = rebuilt.replay(r["decision_digest"], {eng.id: eng}).get("identical", False)
                if not (same_twice and replay_ok):
                    consist_fail.append(c["id"])
            # parity: metamorphic variants for agent cases that don't reference the actor's own entity
            if c["actor"].startswith("agent:") and not c.get("self_scoped") and c["actor"] not in json.dumps(c["ops"]):
                variants = [] if c.get("vendor_sensitive") else [("vendor:" + v, v, None) for v in VENDORS if v != c["actor"]]
                variants.append(("unicode:NFD", c["actor"], _nfd))
                for label, actor, mut in variants:
                    parity_checks += 1
                    v = run_case(eng, c, actor=actor, mutate=mut)
                    if v["outcome"] != r["outcome"]:
                        parity_fail.append(f"{c['id']}[{label}]: {r['outcome']}→{v['outcome']}")
        got = [r["got"] for r in rows]
        exp = [r["expect"] for r in rows]
        matrix = {e: {g: 0 for g in OUTCOMES + ("error", "other")} for e in OUTCOMES}
        for e, g in zip(exp, got):
            matrix[e][g if g in matrix[e] else "other"] += 1
        errors = [r for r in rows if r["got"] != r["expect"]]
        false_allows = [r for r in errors if r["got"] == "allow" or "then:applied" in r["got"]]
        n = len(rows)
        outcomes_by_engine[name] = got
        report["engines"][name] = {
            "engine_id": eng.id,
            "coverage": round(sum(g != "error" for g in got) / n, 4),
            "accuracy": round((n - len(errors)) / n, 4),
            "weighted_correctness": round(max(0.0, 1 - (len(errors) + 2 * len(false_allows)) / n), 4),
            "false_allows": [r["id"] for r in false_allows],
            "adversarial_accuracy": round(sum(r["got"] == r["expect"] for r in rows if r["adversarial"]) /
                                          max(1, sum(r["adversarial"] for r in rows)), 4),
            "review_rate": round(got.count("review") / n, 4),
            "parity": round(1 - len(parity_fail) / max(1, parity_checks), 4),
            "parity_checks": parity_checks,
            "parity_failures": parity_fail,
            "consistency": round(1 - len(consist_fail) / max(1, consist_checks), 4),
            "consistency_failures": consist_fail,
            "latency_ms": {"p50": pct(lat_ms, 0.5), "p99": pct(lat_ms, 0.99), "mean": round(statistics.fmean(lat_ms), 2)},
            "confusion": matrix,
            "mismatches": [{k: r[k] for k in ("id", "category", "expect", "got", "rule_id", "known_gap")} for r in errors],
        }
    names = list(engines)
    if len(names) > 1:
        base = names[0]
        report["portability"] = {}
        for other in names[1:]:
            a, b = outcomes_by_engine[base], outcomes_by_engine[other]
            report["portability"][f"{base}~{other}"] = {
                "kappa": kappa(a, b),
                "agreement": round(sum(x == y for x, y in zip(a, b)) / len(a), 4),
                "allow_agreement": round(sum((x == "allow") == (y == "allow") for x, y in zip(a, b)) / len(a), 4),
                "disagreements": [f"{c['id']}: {x} vs {y}" for c, x, y in zip(cases, a, b) if x != y],
            }
    return report


def to_markdown(rep: dict[str, Any]) -> str:
    lines = ["# Lattice governance eval", "", f"{rep['cases']} cases · suites: {', '.join(rep['suites'])}", "",
             "| engine | coverage | accuracy | weighted | adversarial | parity | consistency | review rate | p50 ms | p99 ms |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for name, e in rep["engines"].items():
        lines.append(f"| {name} (`{e['engine_id']}`) | {e['coverage']:.0%} | {e['accuracy']:.0%} | {e['weighted_correctness']:.0%} | "
                     f"{e['adversarial_accuracy']:.0%} | {e['parity']:.0%} ({e['parity_checks']}) | {e['consistency']:.0%} | "
                     f"{e['review_rate']:.0%} | {e['latency_ms']['p50']} | {e['latency_ms']['p99']} |")
    for name, e in rep["engines"].items():
        if e["mismatches"]:
            lines += ["", f"**{name} mismatches**", ""]
            for m in e["mismatches"]:
                tag = " _(known gap)_" if m["known_gap"] else ""
                lines.append(f"- `{m['id']}` ({m['category']}): expected **{m['expect']}**, got **{m['got']}** via `{m['rule_id']}`{tag}")
        if e["false_allows"]:
            lines.append(f"- ⚠️ false allows: {', '.join(e['false_allows'])}")
        if e["parity_failures"]:
            lines.append(f"- parity failures: {', '.join(e['parity_failures'])}")
    for pair, p in rep.get("portability", {}).items():
        lines += ["", f"**portability {pair}**: κ={p['kappa']}, agreement {p['agreement']:.0%}, allow/not-allow {p['allow_agreement']:.0%}"]
        for d in p["disagreements"][:20]:
            lines.append(f"- {d}")
    return "\n".join(lines) + "\n"


def main(ns) -> None:
    engines: dict[str, Engine] = {"builtin": BuiltinEngine()}
    for spec in ns.with_engine:
        name, _, cmd = spec.partition("=")
        engines[name] = CommandEngine(name, shlex.split(cmd))
    rep = evaluate(engines, load_suites(ns.suite))
    md = to_markdown(rep)
    print(md)
    if ns.out:
        Path(ns.out).write_text(json.dumps(rep, indent=2), encoding="utf-8")
    if ns.markdown:
        Path(ns.markdown).write_text(md, encoding="utf-8")
