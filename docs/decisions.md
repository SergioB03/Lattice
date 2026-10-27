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

## Round 3: multi-vendor consensus and its red-team (Oct 27, 2026)

**Built:** an `endorse` op lets agents vote on other actors' pending proposals, like the Skylr review rounds.
Approval from *k* = 2 distinct vendors can settle low-stakes review findings. One objection sends the proposal to a human.
Overruling a human, suspected injection, history rewrites and schema changes are hard-coded as human-only;
the config refuses to make them eligible.

**Red-team (independent agent), all confirmed and fixed:**

| # | Finding | Fix |
|---|---|---|
| R3-1 (High) | A single agent could invent `agent:codex-x` / `agent:gemini-y` ids and reach "consensus" alone. Vendors came from id prefixes, and ids aren't authenticated | Only **owner-registered voters** count (`lattice voters add agent:codex-rem openai`). Registration is an owner-signed `config.changed` event that the audit checks. Unregistered votes are recorded but can neither approve nor block, so there's no DoS |
| R3-2 (High) | Votes were bound to a proposal id, not to what the voter saw. State drift could turn a harmless insert into overruling someone, and consensus cleared findings no voter saw | Every vote carries the **plan digest** the voter saw (shown in `lattice_review_queue`). An approval counts only if it matches the plan being decided now |
| R3-3 (Med) | Any vote re-decided the target under the *proposer's* hourly rate limit, so one vote could permanently deny it | Decisions record a `trigger`. Rate limits apply only when a proposal is first submitted |
| R3-4 (Low) | Vote floods re-decided on every vote | Only registered votes trigger a re-decide. Proposals are capped at 20 endorsements |
| R3-5 (Low) | Proposals could carry votes, so votes could be voted through in chains | Votes (and withdrawals) must be alone in their proposal, and proposals containing votes can't be voted on |

Engine bumped to `lattice-py/3`.

**What held, according to the red-team:** human-only findings, deny passthrough, self-votes, double votes,
observer votes, owner-passphrase gating, objection blocking, and audit/replay after every consensus path.

## Round 4: a Go engine and a small-model AX test (Oct 27, 2026)

**Go reference engine** (`examples/engines/go`): strict Skylr-style decoding (unknown fields rejected,
fail closed) and a full port of `lattice-py/3`. CI builds it and requires Cohen's κ = 1.0 against the Python
engine over every scenario. It got κ = 1.0 on the first run, and again after round 3's semantics changed.

**Small-model AX test** (an agent role-playing a 9B local model with a 2k-token budget per task):

| Finding | Fix |
|---|---|
| Unknown names said "create it", which produced near-duplicates (High) | Resolution answers "Did you mean project:skylr (90%)? Pass that id." Search is typo-tolerant |
| Denied/pending results listed `created` ids that don't exist (High) | `created` only appears when applied |
| Predicate hints were by spelling only (`written_in` → `located_in`) (Med) | The error also lists predicates that fit the subject type and object/value shape |
| Silent bad status filter; no cheap "what happened to mine" (Med) | `lattice_my_proposals(status="all")` with validation and one-line summaries |
| Pretty-printed JSON doubled token cost (Low) | Compact JSON everywhere |
| Couldn't see own vendor or voter status; couldn't withdraw mistakes (Low) | `whoami` shows vendor and `registered_voter`; new `withdraw` op |

Tool list cost: about 1,540 tokens for 12 tools. It's kept because the `lattice_propose` description carries the copyable example
that let the small model write correctly on its first call.

**Windows check:** `lattice mcp-config` now emits the venv's own Python by absolute path (no PATH or activation needed).
`.vscode/mcp.json` targets `.venv\Scripts\python.exe`, CI covers Windows on Python 3.12 and 3.13, and the CLI forces UTF-8 output.

## Round 5: final pre-release review (Oct 27, 2026)

A reviewer with no prior context tried to break the near-final build. It found five release blockers. All were confirmed, and all are now fixed
with tests (`tests/test_round5.py`) and scenarios.

| # | Finding | Fix |
|---|---|---|
| F1 (blocker) | The owner signature covered only `{id, content_digest}`, so the body could be swapped and the audit still passed | Signatures cover the whole body. The audit recomputes every content digest and proposal id |
| F2 (blocker) | The genesis was unsigned: roles could be rewritten under the same passphrase | The genesis is signed at `init` and verified by the audit. Insecure-dev ledgers are reported as unsigned |
| F3 (blocker) | `--engine` let any shell user pick a yes-to-everything engine | The flag is gone. The engine lives in the owner-signed config (`lattice engine command …`), and command engine ids include a hash of the command |
| F4 (blocker) | The audit trusted the recorded decision clock | The ledger clock is monotonic. The audit requires `now == event time` and timestamps that never decrease |
| F5 (blocker) | Huge proposals were written to the append-only ledger before size checks; 1,500 ops held the write lock for 50 s | Byte, op-count and depth caps are enforced before anything is written |
| F6 | Years before 1000 were formatted with three digits and broke ordering; Python/Go diverged | Years must be 1900 or later with four digits. Go's date parsing fails closed |
| F7 | Agents could claim single-value slots through backdated facts or empty summaries | `trust.claim_slot` covers both (engine `lattice-py/4`, and the Go port too) |
| F8 | An approval could cover a decision recorded after the owner looked | Approvals carry the decision digest the owner saw (CLI and UI) |
| F9/F10 | Stale docs: fixed ids, engine versions, `mcp-config` output, VS Code path; the demo quietly enabled consensus | Docs corrected. The README says the demo registers four voters |
| minor | The UI dropped malformed bodies; deep JSON raised RecursionError; punctuation-only names collided; `mcp-config` didn't validate ids | All return clean errors |

The Go engine still matches the Python engine at κ = 1.0 across all 51 cases.
