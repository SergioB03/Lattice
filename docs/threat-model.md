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
| Agent runs `lattice review approve` or `lattice add --as human:…` from its shell | Approving and writing as a human both need the owner passphrase at an interactive TTY prompt. Agent shells have no TTY. `LATTICE_ALLOW_ENV_PASSPHRASE=1` is an explicit opt-out for your own scripts |
| Claiming the passphrase before the owner does | It's set in the genesis event (`lattice init` prompts). Graphs without one must be created with `--insecure-dev`, and MCP refuses to serve them unless they were |
| Forged events appended with a valid hash chain | `lattice ledger audit` replays the ledger and re-derives every policy input, decision and applied change from prior state. Human-authored events (human writes, approvals, rejections, passphrase changes) carry an HMAC keyed from the owner passphrase, which agents don't know |
| Self-approval | Only the owner can approve, with the passphrase. MCP refuses human actors. An approval acknowledges only the findings the owner saw |
| TOCTOU between decision and apply | Decide and apply run in one `BEGIN IMMEDIATE` transaction. Approval re-plans and re-decides on current state |
| Salami-slicing / flooding | Per-role op limits and hourly rate limits. Identical pending proposals are folded |
| Stored prompt injection | Invisible and bidi characters are stripped on write. Instruction-like text goes to review. All stored text is fenced «» with author and trust when read. `min_trust` filtering |
| Alias / identity hijack | Alias collisions are invalid. Agent alias edits are reviewed. Homoglyph-folded comparison keys |
| Backdated overwrite | Supersession is by valid time. Closing a higher-trust author's fact needs review |
| CSRF / DNS rebinding against the UI | Binds to 127.0.0.1. POSTs need the `X-Lattice` header plus a localhost `Host` and `Origin`. Approvals still need the passphrase |
| XSS via stored text in the UI | All rendering goes through `textContent`, plus a restrictive Content-Security-Policy |
| Cypher injection via predicate or type names | Identifiers are regex-validated before interpolation. Values are always parameters |
| Engine crash or hang | Command engines fail closed (deny) after 10 s |
| Agent swaps the policy engine (`--engine yes-to-everything`) | No such flag. The engine is part of the owner-signed config (`lattice engine …`), and a command engine's id includes a hash of its command |
| Forged decision clock (`now` set to dodge backdating checks or rate limits) | The ledger clock is monotonic, and the audit requires each decision's `now` to equal its event time |
| Rewritten genesis roles under the same passphrase | The genesis (roles, schema, owner) is signed with the owner key and checked by `ledger audit` |
| Owner signature reused on swapped content | Signatures cover the whole proposal body, and the audit recomputes every content digest and proposal id |
| Ledger bloat / long write locks from huge proposals | Size (256 KB), op count (200) and nesting depth are checked before anything is written |

## What's NOT enforced (be honest)

- **A process running as your OS user can edit the SQLite file.** It can't forge owner-signed
  events or ungoverned changes without `lattice ledger audit` noticing. But it can *truncate* history,
  or replace the whole file with a consistent one that has a different passphrase. You'd find that out
  when your passphrase stops working, or when the head no longer matches an anchor. Mitigations:
  - `lattice ledger anchor` and commit the head somewhere agents can't write (another account,
    a phone note, or Skylr's ledger once integrated);
  - run agents under a separate OS user without write access to the DB file, talking to Lattice only through MCP.
- **Consensus inherits that.** Vendors are derived from actor ids, so whoever configures MCP entries could launch
  `agent:codex-fake` and get an "OpenAI" vote. Consensus is therefore limited to low-stakes findings, one objection
  blocks it, and everything that overrules a human stays human-only. Treat consensus as "agents I configured agree",
  not "independent parties agree", until agents carry their own keys.
- **Actor ids aren't authenticated.** Whoever configures an MCP entry chooses its actor id.
  That's attribution, not identity. Per-agent tokens come with the HTTP transport.
- **The instruction-like detector is a heuristic.** Fact-shaped manipulation passes (eval case `I05`).
  Agents must still treat «» text as data.
