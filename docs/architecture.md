# Lattice architecture (v0.1 draft)

Lattice is an in-house knowledge graph that humans and AI agents share.
Agents and humans *propose* changes. A pluggable policy engine decides on each
proposal. Every proposal, decision and applied change lands in a hash-chained
ledger. That makes Lattice a working test target for
[Skylr](https://github.com/SergioB03/Skylr) ("agents propose; the control plane
disposes"), and Skylr can later replace the built-in policy engine without code
changes.

## Problems it is built around

See [research/pain-points.md](research/pain-points.md) for sources. In short:

| Who | What they lack today | Lattice answer |
| --- | --- | --- |
| Humans (UX) | Hairball graph views that answer nothing | Entity cards, timelines and a review queue, not a force-directed blob |
| Humans | Not knowing who wrote a fact, or whether it's still true | Every fact carries actor, source, evidence and bitemporal validity |
| Humans | Duplicate entities and schema drift | Closed, registered schema; aliases; governed merges |
| Humans | Ops burden of running a graph DB just to start | Embedded SQLite is the source of truth; Neo4j is an optional projection |
| Agents (AX) | Writing raw Cypher, hallucinated labels, destructive writes | Typed operations only; `schema` tool; no raw query/write surface |
| Agents | Token blowup from dumping subgraphs | `context` tool with a hard token budget and ranked, compact output |
| Agents | Stale and contradictory memory | Bitemporal facts; cardinality-one predicates supersede instead of piling up |
| Agents | No way to see what other agents wrote, or why | Provenance on every line of output; per-actor history |
| Agents | Silent write failures, or writes that just happen | Every write returns a decision record: allow / deny / review, with a rule id |
| Operators | No audit trail across vendors (Claude, Codex, Ollama…) | One vendor-neutral ledger; actors configured per agent |

## Core model

```
Entity  (id, type, name, aliases[], summary)
Fact    (id, subject → predicate → object_entity | literal value,
         valid_from, valid_to, recorded_at, status, confidence,
         actor, source, evidence, proposal_id)
Schema  (entity types; predicates with domain, range, cardinality)
Proposal(actor, ops[], justification, evidence) -- digest = sha256(canonical JSON)
Decision(engine, proposal digest, policy digest, outcome, rule_id, reason)
Ledger  (seq, ts, type, actor, payload_digest, prev_hash, hash)
```

* **Bitemporal facts.** `valid_from/valid_to` is when the fact is true in the
  world; `recorded_at` is when Lattice learned it. Nothing is deleted:
  retraction and supersession close a fact. `as_of` queries see either
  timeline.
* **Cardinality.** A predicate is `one` or `many`. Asserting a new value for a
  `one` predicate supersedes the current fact. Facts are never left silently
  contradicting each other.
* **Closed schema.** Entity types and predicates must be registered. Unknown
  labels are rejected with a hint listing the nearest registered names. Schema
  changes are themselves proposals, so they get governed too.

## Write path: propose → decide → apply

```
agent/human ──propose(ops)──▶ validate (shape, schema, references)
                                   │ invalid → rejected (never reaches policy)
                                   ▼
                         policy engine (pure function)
                       input = proposal + actor + policy + facts it touches + now
                                   │
              ┌──────────────── allow ─────────── review ─────────── deny
              ▼                                     │                  │
   apply in one SQLite transaction         queue for a human      record + return
   (graph tables + ledger events)          (approve → apply)
```

* The engine is a **pure function**: it reads no clock, files or network. Its
  input is recorded by digest, so any decision can be **replayed** and must
  reproduce the same canonical bytes. This mirrors Skylr's L2 replay.
* Engines are pluggable: `builtin` (Python, versioned `lattice-py/1`) or
  `command` (any executable speaking the JSON-over-stdio protocol in
  [skylr-integration.md](skylr-integration.md)). That's where Skylr plugs in.
* Apply is atomic: graph rows and ledger events commit together or not at all.

## Storage

* **SQLite is the source of truth** for the graph, proposals, decisions and
  ledger. It's embedded, has zero ops, runs on Windows, and allows atomic
  graph-and-audit commits.
* **Neo4j is a projection.** `lattice neo4j sync` replays ledger-applied
  changes into Neo4j (idempotent `MERGE` keyed on Lattice ids), so Bloom,
  Browser, Cypher and GDS work for exploration and analytics. Neo4j never
  receives writes that bypass governance. See ADR-0002.

## Interfaces

| Surface | For | Notes |
| --- | --- | --- |
| Python library `lattice` | code | `Lattice.open(path)` |
| CLI `lattice` | humans, scripts | init, add/new/propose, review, show, search, history, ledger verify/audit/anchor, replay, eval, neo4j sync |
| MCP server `lattice-mcp` | agents | stdio (Claude Code, Codex, VS Code, Antigravity); actor bound per server entry |
| Web UI `lattice ui` | humans | review queue, entity cards, timeline, ledger; stdlib server, no build step |

## Actors and trust

The governed config (stored in the ledger) declares actors (`human:sergio`, `agent:claude-code`,
`agent:codex-rem`, `agent:ollama-qwen`, …) with a role. Roles grant operations
and a trust rank. Each MCP server entry is launched with `LATTICE_ACTOR`, so
every write is attributed. Agent ids are *attribution, not authentication*. The owner is different:
the passphrase is set in the genesis event, human-authored events carry an owner HMAC, and
`lattice ledger audit` re-derives every decision. See [threat-model.md](threat-model.md).

## Skylr test bed

`lattice eval` runs scenario suites (YAML) against one or more engines and
reports neutrality metrics (refined in round 1; see [evals.md](evals.md)). They come from Sergio's open question about
measuring neutrality:

* **Coverage:** share of scenarios that get a well-formed decision (no crash or timeout).
* **Correctness:** share matching the scenario's expected outcome.
* **Parity:** identical proposals from different vendors' agents in the same
  role get identical outcomes.
* **Consistency:** re-evaluating and replaying gives byte-identical decisions.
* **Portability:** two engines (e.g. builtin vs Skylr) agree on outcome.
