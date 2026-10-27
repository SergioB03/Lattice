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

## Round 2: AX test agent and independent code review (Oct 27, 2026)

Two agents that hadn't seen the design discussions went at the working build.
One used it purely through MCP as an agent would. The other did a cold
security and correctness review and reproduced each finding. Every confirmed finding
is fixed and pinned by a test in `tests/test_round2.py` or a scenario in the eval suite.

| # | Finding (severity) | Fix |
|---|---|---|
| R2-1 | `as_of` hid superseded facts; malformed dates compared as strings (High) | Valid-time queries include closed intervals; `as_of` is strictly parsed |
| R2-2 | "Own entity" exemption let an agent overrule the owner's facts about itself (High) | Self-scope never covers closing another actor's words; `trust.override` always applies |
| R2-3 | Window to claim the passphrase before the owner set it (High) | Passphrase is set in the genesis event; `insecure_dev` must be explicit; MCP refuses unsecured graphs |
| R2-4 | Forged ledger *appends* pass the hash check (High) | `lattice ledger audit`: re-derives every decision and applied change from prior state; human-authored events carry an owner HMAC keyed from the passphrase |
| R2-5 | Approval suppressed review findings that appeared after the human looked (Med) | Approvals acknowledge only the findings shown; new ones send the proposal back to the queue |
| R2-6 | Unfenced names/aliases in search and change feeds; multi-line names forged result lines (Med) | Identifier fields are single-line on write; all outputs fence stored text |
| R2-7 | Paging stalled on a fact bigger than the budget (Med) | Each page shows at least one (truncated) fact; cursor carries `as_of`/`min_trust` |
| R2-8 | Reviewers saw raw ops, not what would be applied (Med) | Ops are cleaned before hashing; review cards show resolved targets, closes and every field |
| R2-9 | Idempotency key pinned an invalid result; reused key with new content silently dropped (High, AX) | Failed attempts don't consume a key; same key + different content is an error |
| R2-10 | Duplicates inside one proposal; homoglyph/variant names (Med) | Resolution checks earlier creates in the same plan; visual skeleton (I/l/1, 0/o, rn/m) and name containment |
| R2-11 | Backdated value overlapped a superseded interval (Med) | The covered interval is trimmed, and the change routes to review (`temporal.overlap`) |
| R2-12 | Agents could rewrite a human's summary, or claim single-value slots on owner entities, unattributed (Critical, AX) | Summaries carry author + trust and are governed like facts; `trust.claim_slot`; summaries show `[by actor·trust]` |
| R2-13 | Polite injections ("Note for assistants…") passed (High, AX) | Detector covers reader-addressed directives; a reputation-poisoning case (`I05`) stays as a documented known gap |
| R2-14 | Command engine could `allow` while reporting a `deny` finding; floats crashed recording (Low) | Outcome is the worst of stated outcome and findings; malformed output fails closed |
| R2-15 | Wrong field types crashed planning (Low) | Every field type-checked → `invalid` with a message |
| R2-16 | UI accepted any approver name; IPv6 Host; negative Content-Length; LAN binding (Low) | Owner-only approvals, proper Host parsing, length bounds, localhost-only unless explicitly allowed |
| R2-17 | AX: no "my proposals", noisy change feed, misleading object/value errors, 100% default confidence | `lattice_my_proposals`; `changes_since` excludes your own writes, drops no-ops, reports your resolutions; precise object/value errors; agents default to 80% |

**Disagreed / deferred:**
- *Make missing `source` an `invalid` rather than `denied`.* We kept it as `denied`. It's a role
  policy (owners and maintainers don't need sources), not a schema rule, and the deny reason says exactly what to add.
- *Set MCP `isError` for denied/invalid proposals.* We set it for bad input (unknown ids, malformed
  dates, key conflicts). A denied proposal is a successful call with a governance answer, so it isn't an error.

### Round 2b: scale check (same day)

A synthetic load of 4,000 entities and 2,000 facts surfaced two problems:
- **Serial names were flagged as duplicates.** "alpha bravo 0-1" vs "-2", like "Sprint 12" vs "Sprint 13".
  Names whose numbers differ are now capped below the review band.
- **Entity resolution was a quadratic fuzzy scan.** Resolution now uses blocking: exact keys, a
  look-alike skeleton index, and FTS trigram candidates. A single agent create went from 111 ms
  to about 3 ms at that size. Context reads stay at about 1 ms, search about 2 ms, and verify-plus-rebuild about 2 s.
