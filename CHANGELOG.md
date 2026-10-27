# Changelog

## v0.1.0 (2026-10-27)

First release. It was built in five challenge rounds; each one is logged in [docs/decisions.md](docs/decisions.md).

- **Governed write path.** Typed ops → closed schema → pure policy engine (`lattice-py/3`) → atomic apply.
  Outcomes are allow, review or deny, and every rule fires with a reason.
- **Bitemporal facts.** Valid time and transaction time are tracked separately. Supersession goes by valid time, late history is trimmed into place, and `as_of` reads past states.
- **Ledger.** A Skylr-compatible hash chain (canonical JSON, SHA-256). The graph is rebuildable from it (`ledger verify`).
  `ledger audit` re-derives every decision and checks owner HMAC signatures on human events and config changes.
- **Owner security.** The passphrase is set at genesis, human writes and approvals are owner-only, and approvals acknowledge only the findings the owner saw.
- **Multi-vendor consensus.** The `endorse` op takes votes from owner-registered voters, bound to plan digests. One objection blocks it, and the findings that overrule humans stay human-only.
  Agents can `withdraw` their own pending proposals.
- **Agent surface (MCP, stdio).** 12 tools, token-budgeted cited context, "did you mean" resolution, typo-tolerant search,
  a review queue, change feeds, and stored text fenced as data.
- **Human surface.** A CLI and a local web UI with an entity orbit, review queue and ledger view, protected against CSRF and DNS rebinding.
- **Neo4j projection.** Incremental and exactly-once, with a watermark. Tested against live Neo4j in CI.
- **Governance eval.** 48 scenarios measuring coverage, weighted correctness, metamorphic parity, replay consistency, κ portability and latency.
- **Go reference engine.** Strict decoding, at κ = 1.0 against the Python engine.
- **Tooling.** VS Code tasks, launch configs and MCP config, a dev container with Neo4j, and CI on Linux and Windows (Python 3.12 and 3.13).

Known gaps: fact-shaped manipulation (eval `I05`) needs a semantic judge; agent identity is attribution, not
authentication; there's no streamable-HTTP transport yet.
