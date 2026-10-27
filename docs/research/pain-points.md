# What humans and agents lack: research notes (Oct 2026)

These notes come from issue trackers, docs and papers, gathered Oct 27, 2026.
Each line is a short paraphrase with its source. The right-hand column says
which part of Lattice answers it.

## UX (humans)

| # | Pain | Source | Lattice answer |
|---|------|--------|----------------|
| U1 | GraphRAG-style indexing is expensive up front; Microsoft itself calls the cost prohibitive for some uses | [MS Research, LazyGraphRAG](https://microsoft.com/en-us/research/blog/lazygraphrag-setting-a-new-standard-for-quality-and-cost) | No mandatory LLM extraction; typed writes are free; extraction is opt-in and budgeted |
| U2 | People can't see *why* an answer came out or trace it to records | [graphrag-inspector](https://github.com/workdd/graphrag-inspector) | Every rendered fact carries actor, source and proposal id; `explain` decisions |
| U3 | The same thing becomes several nodes under different names | [LightRAG #1323](https://github.com/HKUDS/LightRAG/issues/1323) | Alias registry + lexical resolution bands + governed merges |
| U4 | Updated facts don't replace old ones; the maintainer's advice is to delete old docs by hand | [LightRAG #2528](https://github.com/HKUDS/LightRAG/issues/2528) | Cardinality-one predicates supersede; history is kept |
| U5 | The graph view is widely seen as pretty but not useful | [Obsidian forum](https://forum.obsidian.md/t/whats-the-point-of-the-graph-view-how-are-you-using-it/71316?page=2) | UI leads with entity cards, timelines and a review queue; the graph is a local 1-hop orbit |
| U6 | Neo4j Browser struggles at a few hundred nodes | [Neo4j community](https://community.neo4j.com/t/trying-to-visualize-the-entire-graph/47527) | Never render the whole graph; bounded neighborhoods |
| U7 | GraphRAG global search is slow (12–15 s before first token) | [GraphRAG #750](https://github.com/microsoft/graphrag/issues/750) | Reads are SQL + FTS, no LLM in the read path |
| U8 | Storage migrations lose data and lock users in (Logseq DB version) | [Logseq forum](https://discuss.logseq.com/t/database-version-too-drastic-choice/20346) | Ledger is the portable truth; `export` to JSONL; Neo4j is a rebuildable projection |
| U9 | Hosted free tiers pause and delete data (AuraDB Free) | [Aura docs](https://neo4j.com/docs/aura/managing-instances/instance-actions/) | Local-first, single file |
| U10 | Index cost is invisible | [GraphRAG #1153](https://github.com/microsoft/graphrag/issues/1153) | Proposals record cost metadata the caller reports |
| U11 | Governance (RBAC, clustering, hot backup) sits in Neo4j Enterprise | [Neo4j open core](https://neo4j.com/open-core-and-neo4j/) | Governance lives above storage, not in it |

## AX (agents)

| # | Pain | Source | Lattice answer |
|---|------|--------|----------------|
| A1 | Mem0 audit: 97.8% of 10k memories were junk; one hallucinated fact stored 808× via a recall→re-extract feedback loop | [Mem0 #4573](https://github.com/mem0ai/mem0/issues/4573) | Idempotent asserts (`already_known`), no auto-extraction, rate limits per actor, provenance kept off re-ingest |
| A2 | HaluMem benchmark: extraction accuracy < 62%, update omission 52–74%, QA hallucination ~19–22% | [arXiv 2511.03506](https://arxiv.org/pdf/2511.03506) | Writes are explicit, typed claims with evidence, not free-form extraction |
| A3 | MCP memory server's `read_graph` dumps 50–80k tokens; tool descriptions don't say when to use what | [servers #3953](https://github.com/modelcontextprotocol/servers/issues/3953), [#5202](https://github.com/modelcontextprotocol/servers/issues/5202) | No whole-graph read; `context` has a hard token budget; every tool description says *when* to use it |
| A4 | Concurrent writes silently corrupt (MCP memory JSON, Graphiti group leak, Cognee duplicate keys, LadybugDB WAL) | [#1819](https://github.com/modelcontextprotocol/servers/issues/1819), [graphiti #1676](https://github.com/getzep/graphiti/issues/1676), [cognee #4394](https://github.com/topoteretes/cognee/issues/4394), [cognee #6170](https://github.com/topoteretes/cognee/issues/6170) | Single SQLite writer with `BEGIN IMMEDIATE`; graph and ledger commit atomically; ledger verify |
| A5 | CVE-2026-35402: regex "read-only" guard in mcp-neo4j-cypher bypassed via APOC | [Wiz](https://www.wiz.io/vulnerability-database/cve/cve-2026-35402) | Agents get no Cypher at all; Neo4j is downstream of governance |
| A6 | Graphiti declined PII/ACL/audit hooks | [graphiti #1679](https://github.com/getzep/graphiti/issues/1679) | Policy engine is the hook; Skylr can plug in |
| A7 | MCP memory ships deletes on by default, no limits, no journal | [servers #4117](https://github.com/modelcontextprotocol/servers/issues/4117) | No delete op exists; retraction is a governed, audited proposal |
| A8 | Mem0 stores contradictions side by side, by design | [Mem0 #4896](https://github.com/mem0ai/mem0/issues/4896) | Cardinality + supersession; conflicts surfaced in context output |
| A9 | Embedding-only dedup misses exact duplicates; Neo4j Labs recommends 3 bands (auto / review / new) | [graphiti #1734](https://github.com/getzep/graphiti/issues/1734), [Neo4j Labs](https://neo4j.com/labs/agent-memory/explanation/resolution-deduplication/) | Exact+alias first, then fuzzy bands; uncertain → review queue |
| A10 | Ingestion cost spikes ($8→$36/day from re-embedding per call) | [cognee #4233](https://github.com/topoteretes/cognee/issues/4233) | Nothing is re-embedded on write |
| A11 | Text2Cypher is the least reliable GraphRAG pattern | [graphrag.com](https://graphrag.com/reference/graphrag/text2cypher/) | Typed ops + `schema` tool |
| A12 | Truncating serialized JSON yields invalid JSON | [mcp-neo4j #303](https://github.com/neo4j-contrib/mcp-neo4j/issues/303) | Budget is applied to rows *before* rendering; output says what was omitted |

## Storage landscape (Oct 2026)

| Option | License | Embedded | Status | Notes for us |
|---|---|---|---|---|
| Neo4j Community | GPLv3 | server | active | Great tooling (Browser, Bloom, GDS); governance features are Enterprise; used here as projection |
| Kùzu | MIT | yes | **archived Oct 2025** (Apple acquisition) | Avoid |
| LadybugDB | MIT | yes | active Kùzu fork, v0.19 | Watch; crash report at ~10k nodes (Oct 2026) |
| FalkorDB | SSPLv1 | Redis module | active | License risk if commercialised |
| Memgraph | BSL / MEL | server | active | License risk |
| Apache AGE | Apache-2.0 | Postgres ext | active (1.7/1.8) | Good future backend if we move to Postgres |
| GraphQLite | MIT | SQLite ext | pre-1.0 | Interesting; immature |

**Conclusion:** keep the source of truth in plain SQLite behind a store interface.
Treat graph engines as projections we can rebuild from the ledger. That way
vendor churn (Kùzu) or license changes can't hurt us.
