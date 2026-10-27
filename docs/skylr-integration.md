# Plugging Skylr (or any engine) into Lattice

Lattice decides every proposal with a **policy engine**. The built-in one is
`lattice-py/1`. Any executable can replace it by speaking this protocol over
stdin/stdout. That's how Skylr governs Lattice, and how Lattice tests Skylr.

```bash
lattice --engine "skylr graph evaluate" ui
lattice eval --with-engine skylr="skylr graph evaluate"
```

## Contract

**Input** (stdin): one canonical JSON document, `kind: lattice.dev/policy-input/v1`.
Canonical means sorted keys, compact, UTF-8, no floats, no nulls. This is the same
subset Skylr's `identity.Canonical` hashes, so `sha256(stdin bytes)` equals the
`input_digest` Lattice records.

| field | meaning |
|---|---|
| `proposal_id`, `proposal` | the proposal as submitted (`lattice.dev/proposal/v1`: actor, ops, justification, idempotency_key, client) |
| `actor` | `{id, role, trust}` resolved from config |
| `role` | the role's full settings (ops → allow/review/deny, limits, require_source, min_confidence_bp) |
| `resolution` | duplicate/review thresholds in basis points |
| `config_digest`, `schema_digest` | digests of the governing config and schema at decision time |
| `ledger_head` | `{seq, hash}` the decision was made against |
| `now` | UTC millisecond timestamp. **Engines must not read a clock.** |
| `approval` | `{by, role, trust}` when a human is approving a queued proposal, else empty strings and 0 |
| `plan[]` | per op: `index, op, effect` (create / insert / supersede / historical / noop / retract / alias / summary / define), `target`, `has_source`, `confidence_bp`, `closes[]` (facts it would close, with author and trust), `best_match` (entity resolution), `instruction_like` |
| `read_set[]` | everything the core read to build the plan, **including negative reads** (an empty `facts` list means "no current fact") |
| `aggregates` | `proposals_last_hour` for the actor |
| `endorsements` | votes on this proposal: `{actor, vendor, verdict}` |
| `consensus` | `{k, eligible}`: how many distinct vendors, and which findings they may settle |

**Output** (stdout): JSON with `outcome` (`allow` \| `review` \| `deny`), `rule_id`
and `reason`, plus optional `findings[]` (`rule_id, outcome, op_index, detail`).

**Failure semantics:** non-zero exit, timeout (10 s), unparsable output or a
missing field all become **deny** with `rule_id: engine.error`. The system fails closed.

**Determinism:** Lattice stores the input and the decision. `lattice replay` re-runs
the engine and requires byte-identical decision JSON. An engine that reads files,
network or time will fail the eval's consistency metric.

## Mapping to Skylr concepts

| Skylr | Lattice |
|---|---|
| Candidate / mission | Proposal (`ops` = the change set, `justification` = intent) |
| `policy.Input` with input digests | `lattice.dev/policy-input/v1` + `input_digest` |
| `policy.Decision` (`engine_version`, `outcome`, `rule_id`, `reason`) | `lattice.dev/policy-decision/v1` (same fields) |
| L2 replay | `lattice replay` / eval consistency |
| Ledger header (`seq, run_id, ts, type, actor, payload_digest, prev_hash`) | identical header, identical hash rule |
| Narrowing rules (limits only decrease) | roles: `ops`, `max_*`, `require_source`, `min_confidence_bp` |

## Reference implementation in Go

[`examples/engines/go/main.go`](../examples/engines/go/main.go) is a complete engine in Skylr's language:
- typed structs for the whole input, `DisallowUnknownFields`, and no trailing data;
- a port of `lattice-py/2`, including consensus.

CI builds it and requires Cohen's κ = 1.0 against the Python engine across every scenario. A Skylr engine can start
from this file and then tighten the policy. The eval then shows exactly where Skylr diverges.

## Suggested Skylr milestone

1. `skylr graph evaluate`: decode the input with the same strict decoder rules
   (unknown fields rejected), apply typed policy, print a decision.
2. Anchor Lattice's ledger head in Skylr's ledger (`lattice ledger anchor` → a Skylr event),
   so Lattice history is authenticated against a store agents can't rewrite.
3. Run `lattice eval --with-engine skylr=...` in Skylr's CI. Portability κ against
   `lattice-py/1` and zero false allows are the gates.
