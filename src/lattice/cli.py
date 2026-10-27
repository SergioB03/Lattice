"""`lattice` command-line interface (for humans and scripts)."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shlex
import sys
from pathlib import Path

import yaml

from .core import AuthError, Lattice, LatticeError, default_db_path

BOLD, DIM, GREEN, YELLOW, RED, CYAN, MAGENTA, RESET = (
    ("\033[1m", "\033[2m", "\033[32m", "\033[33m", "\033[31m", "\033[36m", "\033[35m", "\033[0m")
    if sys.stdout.isatty() and not os.environ.get("NO_COLOR") else ("",) * 8
)
OUTCOME_COLOR = {"applied": GREEN, "allowed": GREEN, "pending": YELLOW, "denied": RED, "invalid": RED, "rejected": RED}

BANNER = f"""{CYAN}    ╭─╮   ╭─╮   ╭─╮
    │L├───┤A├───┤T│   {BOLD}Lattice{RESET}{CYAN}
    ╰┬╯   ╰┬╯   ╰┬╯   {RESET}{DIM}a governed knowledge graph for humans + agents{RESET}{CYAN}
     ╰──┬──┴──┬──╯    {RESET}{DIM}agents propose · policy disposes · the ledger remembers{RESET}{CYAN}
      ╭─┴╮   ╭┴─╮
      │T ├───┤I │ …CE
      ╰──╯   ╰──╯{RESET}"""


def _out(obj) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def _result(res: dict) -> None:
    st = res.get("status", "")
    c = OUTCOME_COLOR.get(st, "")
    print(f"{c}{BOLD}{st.upper()}{RESET} {res.get('proposal_id', '')}  {DIM}{res.get('rule_id', '')}{RESET}")
    if res.get("reason") and st != "applied":
        print(f"  {res['reason']}")
    for e in res.get("errors", []):
        print(f"  {RED}op {e['op_index']}{RESET}: {e['error']}")
    for e in res.get("effects", []):
        print(f"  {GREEN}+{RESET} {e}")
    if res.get("deduplicated"):
        print(f"  {DIM}(deduplicated: {res['deduplicated']}){RESET}")


def _open(ns, create: bool = False) -> Lattice:
    engine = None
    if getattr(ns, "engine", None):
        from .policy import CommandEngine
        engine = CommandEngine("custom", shlex.split(ns.engine))
    lat = Lattice.open(ns.db, engine=engine, create=create)
    if not create and not lat.initialized:
        raise LatticeError(f"{ns.db} is not initialized; run `lattice init`")
    return lat


def _passphrase(ns, prompt: str = "owner passphrase: ") -> str:
    # Interactive only, on purpose: agents with a shell have no TTY to answer this prompt.
    if os.environ.get("LATTICE_ALLOW_ENV_PASSPHRASE") == "1" and os.environ.get("LATTICE_OWNER_PASSPHRASE"):
        return os.environ["LATTICE_OWNER_PASSPHRASE"]
    if not sys.stdin.isatty():
        raise AuthError("this needs the owner passphrase at an interactive terminal")
    return getpass.getpass(prompt)


def cmd_init(ns) -> None:
    lat = _open(ns, create=True)
    pw = None
    if not ns.insecure_dev:
        print("Choose the owner passphrase. You'll need it to approve agent proposals and to write as yourself.")
        pw = _passphrase(ns, "new owner passphrase: ")
        if sys.stdin.isatty() and getpass.getpass("again: ") != pw:
            raise AuthError("passphrases differ")
    lat.init(owner=ns.owner, passphrase=pw, insecure_dev=ns.insecure_dev)
    print(BANNER)
    print(f"\n{GREEN}initialized{RESET} {ns.db}  owner={ns.owner}" + (f"  {YELLOW}(insecure dev mode){RESET}" if ns.insecure_dev else ""))
    if ns.demo:
        from .demo import seed
        seed(lat, ns.owner, pw)
        print(f"{GREEN}seeded{RESET} demo graph: {lat.stats()['entities']} entities, {lat.stats()['facts_current']} facts")
    print(f"next: {CYAN}lattice ui --open{RESET}  or  {CYAN}lattice mcp-config claude agent:claude-code{RESET}")


def cmd_passphrase(ns) -> None:
    lat = _open(ns)
    if not sys.stdin.isatty():
        raise AuthError("changing the passphrase needs an interactive terminal")
    old = getpass.getpass("current passphrase: ") if lat.owner_secured else ""
    new = getpass.getpass("new passphrase: ")
    if new != getpass.getpass("again: "):
        raise AuthError("passphrases differ")
    lat.set_owner_passphrase(new, old)
    print(f"{GREEN}owner passphrase set{RESET}")


def _pp(ns, lat: Lattice) -> str | None:
    return _passphrase(ns) if ns.actor.startswith("human:") and lat.owner_secured else None


def cmd_propose(ns) -> None:
    lat = _open(ns)
    raw = sys.stdin.read() if ns.file == "-" else Path(ns.file).read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    if isinstance(data, list):
        data = {"ops": data}
    res = lat.propose(ns.actor, data["ops"], data.get("justification", ""), idempotency_key=data.get("idempotency_key", ""),
                      passphrase=_pp(ns, lat))
    _out(res) if ns.json else _result(res)


def cmd_add(ns) -> None:
    """Quick human entry: lattice add "Sergio" works_on Skylr  |  lattice add Skylr status active"""
    lat = _open(ns)
    pred = lat.schema.predicates.get(ns.predicate)
    op = {"op": "assert", "subject": ns.subject, "predicate": ns.predicate}
    if pred is not None and pred.is_literal:
        op["value"] = ns.object
    else:
        op["object"] = ns.object
    if ns.source:
        op["source"] = ns.source
    if ns.since:
        op["valid_from"] = ns.since
    res = lat.propose(ns.actor, [op], ns.why or "", passphrase=_pp(ns, lat))
    _out(res) if ns.json else _result(res)


def cmd_new(ns) -> None:
    lat = _open(ns)
    op = {"op": "create_entity", "type": ns.type, "name": ns.name}
    if ns.summary:
        op["summary"] = ns.summary
    if ns.alias:
        op["aliases"] = ns.alias
    res = lat.propose(ns.actor, [op], ns.why or "", passphrase=_pp(ns, lat))
    _out(res) if ns.json else _result(res)


def cmd_review(ns) -> None:
    lat = _open(ns)
    if ns.action == "list":
        items = lat.list_proposals("pending", limit=ns.limit)
        if ns.json:
            return _out(items)
        if not items:
            print(f"{GREEN}review queue is empty{RESET} ✨")
        for p in items:
            print(f"{YELLOW}●{RESET} {BOLD}{p['proposal_id']}{RESET} {MAGENTA}{p['actor']}{RESET}  {DIM}{p['received_at']}{RESET}")
            print(f"    {p.get('rule_id', '')}: {p.get('reason', '')}")
            if p["proposal"]["justification"]:
                print(f"    why: «{p['proposal']['justification']}»")
            for e in p["endorsements"]:
                mark = f"{GREEN}+{RESET}" if e["verdict"] == "approve" else f"{RED}✗{RESET}"
                print(f"    {mark} {e['actor']} ({e['vendor']})" + (f": «{e['reason']}»" if e["reason"] else ""))
            if p["consensus"]:
                print(f"    {DIM}{p['consensus']}{RESET}")
            for op in p["proposal"]["ops"]:
                print(f"    {DIM}{json.dumps(op, ensure_ascii=False)}{RESET}")
        return
    if not ns.id:
        raise LatticeError("give a proposal id")
    if ns.action == "show":
        st = lat.proposal_status(ns.id)
        st["proposal"] = json.loads(lat.conn.execute("SELECT body FROM proposals WHERE id=?", (ns.id,)).fetchone()[0])
        return _out(st)
    who = ns.as_actor or lat.owner
    if ns.action == "approve":
        _result(lat.approve(ns.id, who, _passphrase(ns)))
    elif ns.action == "reject":
        _result(lat.reject(ns.id, who, _passphrase(ns), ns.reason or "rejected"))


def cmd_show(ns) -> None:
    lat = _open(ns)
    print(lat.context(ns.entity, budget_tokens=ns.budget, as_of=ns.as_of or "", min_trust=ns.min_trust))


def cmd_search(ns) -> None:
    lat = _open(ns)
    hits = lat.search(ns.query, limit=ns.limit)
    if ns.json:
        return _out(hits)
    for h in hits:
        print(f"{CYAN}{h['id']}{RESET}  {h['name']}  {DIM}{h['score_bp'] // 100}% {h['summary'][:60]}{RESET}")


def cmd_history(ns) -> None:
    lat = _open(ns)
    eid = lat.entity(ns.entity)["id"]
    for f in lat.history(ns.entity, limit=ns.limit):
        print(lat.fact_line(f, perspective="out" if f["subject"] == eid else "in"))


def cmd_ledger(ns) -> None:
    lat = _open(ns)
    if ns.action == "verify":
        r = lat.verify()
        ok = r["rebuild_matches"]
        print(f"{GREEN if ok else RED}{'✔' if ok else '✘'}{RESET} {r['events']} events, chain intact; "
              f"rebuild from ledger {'matches' if ok else 'DIFFERS'}\n  head {r['head']}")
        if not ok:
            sys.exit(1)
    elif ns.action == "audit":
        pw = _passphrase(ns) if lat.owner_secured and not ns.no_passphrase else ""
        r = lat.audit(pw)
        ok = r["ok"]
        print(f"{GREEN if ok else RED}{'✔' if ok else '✘'}{RESET} deep audit: {r['events']} events, {r['decisions_checked']} decisions "
              f"re-derived, {r['applies_checked']} applies re-planned, {r['macs_verified']} owner signatures verified"
              + (f", {r['macs_unverifiable']} unverifiable (no/old passphrase)" if r["macs_unverifiable"] else ""))
        for p in r["problems"]:
            print(f"  {RED}•{RESET} {p}")
        if not ok:
            sys.exit(1)
    elif ns.action == "anchor":
        _out(lat.anchor())
    elif ns.action == "tail":
        from . import ledger as lg
        evs = list(lg.iter_events(lat.conn, after_seq=max(0, lat.head()[0] - ns.limit)))
        for e in evs:
            print(f"{DIM}{e.seq:>5}{RESET} {e.ts} {CYAN}{e.type:<20}{RESET} {MAGENTA}{e.actor}{RESET} {DIM}{e.hash[:19]}…{RESET}")
    elif ns.action == "export":
        for line in lat.export_jsonl():
            print(line)


def cmd_replay(ns) -> None:
    lat = _open(ns)
    digests = [ns.digest] if ns.digest else [r[0] for r in lat.conn.execute("SELECT digest FROM decisions ORDER BY seq")]
    bad = 0
    for d in digests:
        r = lat.replay(d)
        ok = r.get("identical")
        bad += 0 if ok else 1
        if ns.digest or not ok:
            _out(r)
    print(f"{GREEN if not bad else RED}{len(digests) - bad}/{len(digests)} decisions replayed byte-identical{RESET}")
    sys.exit(1 if bad else 0)


def cmd_stats(ns) -> None:
    _out(_open(ns).stats())


def cmd_ui(ns) -> None:
    from .ui import serve
    serve(_open(ns), host=ns.host, port=ns.port, open_browser=ns.open)


def cmd_eval(ns) -> None:
    from .evals import main as eval_main
    eval_main(ns)


def cmd_neo4j(ns) -> None:
    from .neo4j_sync import sync_from_env
    _out(sync_from_env(_open(ns), rebuild=ns.rebuild))


def cmd_voters(ns) -> None:
    lat = _open(ns)
    if ns.action == "list":
        for v in lat.config.data.get("voters", []):
            print(f"{CYAN}{v['actor']}{RESET}  {v['vendor']}")
        if not lat.config.data.get("voters"):
            print("no registered voters: multi-vendor consensus is off")
        return
    if not ns.actor_id:
        raise LatticeError("give an agent id")
    data = lat.config.data
    if ns.action == "add":
        if not ns.vendor:
            raise LatticeError("give a vendor, e.g. lattice voters add agent:codex-rem openai")
        lat.register_voter(ns.actor_id, ns.vendor, _passphrase(ns) if lat.owner_secured else "")
    else:
        data["voters"] = [v for v in data.get("voters", []) if v["actor"] != ns.actor_id]
        lat.set_config(data, _passphrase(ns) if lat.owner_secured else "")
    print(f"{GREEN}ok{RESET}")


def cmd_mcp_config(ns) -> None:
    """Print client config using this interpreter's absolute path, so it works without PATH or venv activation."""
    db = str(Path(ns.db).resolve())
    actor = ns.actor_id
    py = sys.executable
    args = ["-m", "lattice.mcp_server", "--db", db]
    name = "lattice-" + actor.split(":")[1]
    if ns.client == "claude":
        quoted = " ".join(f'"{a}"' if " " in a else a for a in [py, *args])
        print(f"claude mcp add {name} -e LATTICE_ACTOR={actor} -- {quoted}")
    elif ns.client == "codex":
        print(f"[mcp_servers.{name.replace('-', '_')}]\ncommand = {json.dumps(py)}\nargs = {json.dumps(args)}\n"
              f'env = {{ LATTICE_ACTOR = "{actor}" }}')
    elif ns.client == "vscode":
        _out({"servers": {name: {"type": "stdio", "command": py, "args": args, "env": {"LATTICE_ACTOR": actor}}}})
    else:
        _out({"mcpServers": {name: {"command": py, "args": args, "env": {"LATTICE_ACTOR": actor}}}})


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="lattice", description="Lattice: a governed knowledge graph for humans and agents.")
    ap.add_argument("--db", default=default_db_path(), help="database path (env LATTICE_DB; default .lattice/lattice.db)")
    ap.add_argument("--engine", default="", help="external policy engine command (e.g. 'skylr graph evaluate')")
    sub = ap.add_subparsers(dest="cmd", required=True)
    me = os.environ.get("LATTICE_ACTOR", "")

    s = sub.add_parser("init", help="create a new graph")
    s.add_argument("--owner", default="human:owner")
    s.add_argument("--demo", action="store_true", help="seed a small demo graph")
    s.add_argument("--insecure-dev", action="store_true", help="no owner passphrase (throwaway graphs, tests)")
    s.set_defaults(fn=cmd_init)

    o = sub.add_parser("owner", help="owner secret")
    o.add_argument("action", choices=["set-passphrase"])
    o.set_defaults(fn=cmd_passphrase)

    def actor_arg(p):
        p.add_argument("--as", dest="actor", default=me or None, help="actor id (env LATTICE_ACTOR); default: the owner")
        p.add_argument("--json", action="store_true")

    s = sub.add_parser("propose", help="submit ops from a YAML/JSON file (or - for stdin)")
    s.add_argument("file")
    actor_arg(s)
    s.set_defaults(fn=cmd_propose)

    s = sub.add_parser("add", help='quick fact: lattice add "Sergio" works_on Skylr')
    s.add_argument("subject")
    s.add_argument("predicate")
    s.add_argument("object")
    s.add_argument("--source", default="")
    s.add_argument("--since", default="", help="valid_from date")
    s.add_argument("--why", default="")
    actor_arg(s)
    s.set_defaults(fn=cmd_add)

    s = sub.add_parser("new", help='quick entity: lattice new project "Skylr" --summary "..."')
    s.add_argument("type")
    s.add_argument("name")
    s.add_argument("--summary", default="")
    s.add_argument("--alias", action="append", default=[])
    s.add_argument("--why", default="")
    actor_arg(s)
    s.set_defaults(fn=cmd_new)

    s = sub.add_parser("review", help="the human review queue")
    s.add_argument("action", choices=["list", "show", "approve", "reject"])
    s.add_argument("id", nargs="?")
    s.add_argument("--reason", default="")
    s.add_argument("--as", dest="as_actor", default="")
    s.add_argument("--limit", type=int, default=30)
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_review)

    s = sub.add_parser("show", help="entity card (same text agents get)")
    s.add_argument("entity")
    s.add_argument("--budget", type=int, default=1500)
    s.add_argument("--as-of", default="")
    s.add_argument("--min-trust", type=int, default=0)
    s.set_defaults(fn=cmd_show)

    s = sub.add_parser("search")
    s.add_argument("query")
    s.add_argument("--limit", type=int, default=10)
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_search)

    s = sub.add_parser("history")
    s.add_argument("entity")
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(fn=cmd_history)

    s = sub.add_parser("ledger", help="verify | audit | anchor | tail | export")
    s.add_argument("action", choices=["verify", "audit", "anchor", "tail", "export"])
    s.add_argument("--no-passphrase", action="store_true", help="audit without checking owner signatures")
    s.add_argument("--limit", type=int, default=25)
    s.set_defaults(fn=cmd_ledger)

    s = sub.add_parser("replay", help="re-run recorded decisions and check they are byte-identical")
    s.add_argument("digest", nargs="?")
    s.set_defaults(fn=cmd_replay)

    s = sub.add_parser("stats")
    s.set_defaults(fn=cmd_stats)

    s = sub.add_parser("ui", help="local web UI")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--open", action="store_true")
    s.set_defaults(fn=cmd_ui)

    s = sub.add_parser("eval", help="run the governance scenario suite and print neutrality metrics")
    s.add_argument("--suite", action="append", default=[], help="scenario YAML (default: built-in suites)")
    s.add_argument("--with-engine", action="append", default=[], metavar="NAME=COMMAND",
                   help="extra engine to compare, e.g. skylr='skylr graph evaluate'")
    s.add_argument("--out", default="", help="write JSON report here")
    s.add_argument("--markdown", default="", help="write Markdown report here")
    s.set_defaults(fn=cmd_eval)

    s = sub.add_parser("neo4j", help="project the ledger into Neo4j")
    s.add_argument("action", choices=["sync"])
    s.add_argument("--rebuild", action="store_true", help="wipe Lattice nodes in Neo4j and replay from seq 0")
    s.set_defaults(fn=cmd_neo4j)

    s = sub.add_parser("voters", help="who may vote in multi-vendor consensus (owner only)")
    s.add_argument("action", choices=["list", "add", "remove"])
    s.add_argument("actor_id", nargs="?", default="")
    s.add_argument("vendor", nargs="?", default="")
    s.set_defaults(fn=cmd_voters)

    s = sub.add_parser("mcp-config", help="print MCP config for an agent client")
    s.add_argument("client", choices=["claude", "codex", "vscode", "json"])
    s.add_argument("actor_id", help="e.g. agent:claude-code")
    s.set_defaults(fn=cmd_mcp_config)
    return ap


def main(argv: list[str] | None = None) -> None:
    for stream in (sys.stdout, sys.stderr):  # Windows consoles default to cp1252; Lattice prints «» and ✔
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    ns = build_parser().parse_args(argv)
    if getattr(ns, "actor", "x") is None:
        try:
            ns.actor = Lattice.open(ns.db, create=False).owner
        except LatticeError:
            ns.actor = "human:owner"
    try:
        ns.fn(ns)
    except (LatticeError, AuthError, ValueError) as exc:
        print(f"{RED}error:{RESET} {exc}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
