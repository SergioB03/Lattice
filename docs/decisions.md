# Decision log and challenge rounds

Lattice is built the way Skylr is: claims get challenged before code exists.
This file records each decision, the strongest argument against it, and what
we did about it. Later rounds append; nothing gets rewritten.

## Round 1: research + red-team review of the v0.1 draft (Oct 27, 2026)

Inputs: [research/pain-points.md](research/pain-points.md) and an
independent red-team review of [architecture.md](architecture.md) by an agent
that hadn't seen any code.

| # | Decision | Strongest challenge | Disposition |
|---|----------|--------------------|-------------|
| D1 | SQLite is the source of truth; graph DBs are projections | Hand-written traversal in SQL; projections drift | **Kept.** Kùzu was archived in 2025 and FalkorDB/Memgraph carry SSPL/BSL; vendor churn is the bigger risk. Drift is handled by projecting from the ledger with a `seq` watermark, which is rebuildable |
| D2 | Neo4j sync in v0.1 | Cut it to ship faster | **Partly overruled.** Neo4j was an explicit requirement. It ships as a small idempotent projector with a watermark, tested against a live Neo4j in CI |
| D3 | Agents get no Cypher | Multi-hop questions become N tool calls | **Kept**, plus typed `neighbors` (depth ≤ 2) and `path` tools. Cypher is for humans, in Neo4j Browser |
| D4 | Every write goes propose → decide → apply | "Review" blocks agents; they re-propose and flood the queue | **Changed.** `propose` never blocks and returns `pending` + id. Agents see their own pending writes in `context`. Proposals dedupe by digest + idempotency key. Writes about an agent's own entity are auto-allowed. Per-actor rate limits |
| D5 | Closed schema | Bootstrap problem; agents bend nearest predicate | **Kept.** Starter schema ships; `note` and `related_to` are escape valves; unknown names get "did you mean" hints. Schema digest is part of every decision input |
| D6 | Cardinality-one supersession by arrival | Late-arriving facts, backdating attacks | **Changed.** Supersession is by `valid_from`, not arrival. Late facts are inserted as closed historical intervals. A lower-trust actor can't close a higher-trust actor's fact without review |
| D7 | Decide, then apply | TOCTOU: decided on state A, applied to state B | **Changed.** Decide and apply run in one `BEGIN IMMEDIATE` transaction. Approving a queued proposal re-decides on fresh state and records a new decision |
| D8 | Pure policy engine | What must the input closure hold for honest replay? | **Specified.** It holds the proposal, actor record, config digest, schema digest, engine id, ledger head, `now`, a core-computed read set **including negative reads**, and actor aggregates. The engine fetches nothing. `command` engines fail closed |
| D9 | `confidence` as a float | Breaks the canonical-JSON no-floats rule | **Changed.** Integer basis points, 0–10000 |
| D10 | `LATTICE_ACTOR` env var identifies agents | Agents with a shell can run `lattice review approve` as the human | **Changed.** MCP exposes no approve/schema/policy ops. Human approvals need an owner passphrase typed at an interactive prompt (scrypt hash stored). The ledger head can be anchored externally (`lattice ledger anchor`). Threat model written down: on one OS account this is tamper-evident, not tamper-proof |
| D11 | Stored text fed back to agents | Stored prompt injection via evidence/literals | **Changed.** `context` fences all stored text as quoted data with actor + trust. Control and bidi characters are stripped on write. Instruction-like text in a proposal routes to review. Readers can pass `min_trust` |
| D12 | `context` as main read tool | No search quality, no pagination, silent omissions | **Changed.** SQLite FTS5 search; ambiguous names return candidates. Cursors are pinned to a ledger `seq`. Every response ends with an omission report. `changes_since(seq)` lets agents catch up. Every line cites a fact id |
| D13 | Five eval metrics | Each one is gameable (always-deny gets 100% coverage, etc.) | **Changed.** Correctness is a confusion matrix weighting false-allows. Parity is metamorphic (swap vendor, same role). Portability is Cohen's κ. Latency p50/p99 per engine |
| D14 | Streamable HTTP MCP transport | Adds an auth surface | **Cut** for v0.1; stdio only |
| D15 | Entity merges | Alias/merge hijack | **Cut** to aliases only; alias edits are governed |
