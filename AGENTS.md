# Working on the Lattice codebase (for AI agents)

Read `docs/architecture.md` and `docs/decisions.md` first. Decisions there were challenged
and settled; reopen one by adding a new round to `docs/decisions.md`, not by silently changing code.

## Invariants: don't break these

1. **The ledger is the source of truth.** Graph tables change only through `store.apply_event`.
   `lattice ledger verify` (rebuild-from-ledger equality) must stay green.
2. **Engines are pure.** No clock, file, network or randomness inside `policy.py` engines.
   Anything a rule needs goes into the policy input closure built in `core._decide_and_apply` / `core._plan`.
   If you change built-in semantics, bump `BuiltinEngine.id` (`lattice-py/N`).
3. **Canonical JSON only:** no floats, no nulls in anything hashed. Confidence is an integer percent;
   it's stored in basis points.
4. **No agent write path outside `propose`.** Never add approve/delete/raw-query tools to `mcp_server.py`.
5. **Stored text is untrusted.** Clean it on write (`text.clean`), fence it on read (`text.quote`), and
   render it with `textContent` in the UI.
6. **No Cypher string interpolation** except validated identifiers (`neo4j_sync.rel_type/label`).

## Commands

```bash
pip install -e ".[all,dev]"
python -m pytest -q
lattice eval                           # must not regress; add a case for every bug you fix
ruff check src tests
```

When you fix a governance bug, add a scenario to `src/lattice/data/scenarios/` that would have caught it.
