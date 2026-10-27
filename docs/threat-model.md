# Threat model (v0.1)

## Assets

The graph's integrity (no unreviewed high-impact writes), its provenance (who wrote
what), and its history (nothing silently rewritten).

## Actors

| Actor | Capability | Trusted for |
|---|---|---|
| Owner (human) | CLI with a TTY, UI, owner passphrase | everything |
| MCP agent | only the MCP tools of its own server entry | proposing; free writes about itself |
| Agent with a shell (Claude Code, Codex…) | can run any command as the OS user | nothing beyond its MCP role, *in intent* |
| Remote web page | can make your browser send requests to localhost | nothing |

## What's enforced

| Threat | Control |
|---|---|
| Agent writes bypass review | MCP exposes only `propose`; the policy decides. There are no delete, approve or Cypher tools |
| Agent runs `lattice review approve` or `lattice add --as human:…` from its shell | Approving, and writing as a human once a passphrase exists, both need the owner passphrase at an interactive TTY prompt. Agent shells have no TTY. `LATTICE_ALLOW_ENV_PASSPHRASE=1` is an explicit opt-out for your own scripts |
| Self-approval | Approvers must be `human:` actors with the passphrase. MCP refuses human actors |
| TOCTOU between decision and apply | Decide and apply run in one `BEGIN IMMEDIATE` transaction. Approval re-plans and re-decides on current state |
| Salami-slicing / flooding | Per-role op limits and hourly rate limits. Identical pending proposals are folded |
| Stored prompt injection | Invisible and bidi characters are stripped on write. Instruction-like text goes to review. All stored text is fenced «» with author and trust when read. `min_trust` filtering |
| Alias / identity hijack | Alias collisions are invalid. Agent alias edits are reviewed. Homoglyph-folded comparison keys |
| Backdated overwrite | Supersession is by valid time. Closing a higher-trust author's fact needs review |
| CSRF / DNS rebinding against the UI | Binds to 127.0.0.1. POSTs need the `X-Lattice` header plus a localhost `Host` and `Origin`. Approvals still need the passphrase |
| XSS via stored text in the UI | All rendering goes through `textContent`, plus a restrictive Content-Security-Policy |
| Cypher injection via predicate or type names | Identifiers are regex-validated before interpolation. Values are always parameters |
| Engine crash or hang | Command engines fail closed (deny) after 10 s |

## What's NOT enforced (be honest)

- **A process running as your OS user can edit the SQLite file.** It could replace the
  passphrase hash or rewrite rows and recompute the hash chain. The ledger makes
  inconsistent edits *evident* (`lattice ledger verify` also rebuilds and compares), but it can't
  stop someone who rewrites everything consistently. Mitigations:
  - `lattice ledger anchor` and commit the head somewhere agents can't write (another account,
    a phone note, or Skylr's ledger once integrated);
  - run agents under a separate OS user without write access to the DB file, talking to Lattice only through MCP.
- **Actor ids aren't authenticated.** Whoever configures an MCP entry chooses its actor id.
  That's attribution, not identity. Per-agent tokens come with the HTTP transport.
- **The instruction-like detector is a heuristic.** Paraphrased injections pass (eval case `I04`).
  Agents must still treat «» text as data.
