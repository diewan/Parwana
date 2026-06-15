# Agent Workflow — Context-Scoped Development

This directory turns `development/REMAINING_TASKS.md` into a working backlog
that AI agents (Claude, Claude Code, etc.) can execute **one atomic ticket at
a time**, without ever needing the whole ~1M-token monorepo in context.

It does not change anything about the protocol's security rules — every
`.agents/AGENT.md` still applies in full. It only changes *how much of the
repo* gets loaded into a session before an agent starts working.

## The core idea

A task on this codebase almost never needs more than:

1. The file(s) actually being changed.
2. The trait/interface definitions those files must satisfy.
3. The crate's `AGENT.md` (security invariants — ~1.2k tokens, always worth
   including).
4. For "this chain adapter does X correctly, this one doesn't" tasks: a
   short excerpt from the adapter that already does it right.
5. A list of every other place in the repo with the same pattern, so the
   agent doesn't have to grep the whole tree itself (AGENT.md §5.1 already
   *requires* that search — this just does it once, outside the session,
   instead of inside it).

That's a 10–60k token bundle instead of a 1M token one, for the vast
majority of the ~33 atomic tickets in `development/tickets/TICKETS_INDEX.md`.

## Lifecycle

```
TICKETS_INDEX.md ──► pick a ticket ──► flesh it out with TICKET_TEMPLATE.md
                                              │
                                              ▼
                              generate_context_pack.py <ticket>.md
                                              │
                                              ▼
                         development/agent-workflow/context_packs/<ID>_context.md
                                              │
                                              ▼
                new agent session, cwd = the ticket's crate directory,
                paste the context pack as the first message
                                              │
                                              ▼
                  agent edits target file(s), runs the ticket's
                  `verify_commands` (scoped cargo check/test — cheap)
                                              │
                                              ▼
            if this ticket is a "reference" for a repeated pattern
            (most Theme-A adapter tickets are): write a short
            pattern_notes/<ID>.md — see PATTERN_NOTE_TEMPLATE.md
                                              │
                                              ▼
              mark ticket DONE in TICKETS_INDEX.md, commit
                                              │
                                              ▼
   after a batch of tickets (e.g. one full theme), run the expensive
   full-workspace checks once: `cargo build --workspace --all-features`,
   `cargo test --workspace --all-features`, the architecture constitution
   suite, and `cargo fmt --all -- --check` / clippy.
```

## Step-by-step

### 1. Pick a ticket

Open `development/tickets/TICKETS_INDEX.md`. Pick anything marked
`status: open`. Tickets are intentionally small — most map to one file and
one trait surface. If you're warming up the workflow for the first time,
start with `F-CODEC-001` (low risk, low blast radius).

If the ticket file doesn't exist yet (the index has a row but no `.md`),
copy `TICKET_TEMPLATE.md` to `development/tickets/<ID>.md` and fill in the
frontmatter — it takes 5–10 minutes and you only do it once per ticket, ever.

### 2. Generate the context pack

```bash
python3 development/agent-workflow/generate_context_pack.py \
    development/tickets/<ID>.md
```

This writes `development/agent-workflow/context_packs/<ID>_context.md` and
prints a rough token-size estimate. It:

- pulls the **current** snippet around each `target_pattern` (line numbers
  in REMAINING_TASKS.md drift — this re-finds them live with `rg`/`grep`),
- runs a repo-wide occurrence search for each pattern and lists every hit,
  satisfying AGENT.md §5.1 without spending agent tokens on it,
- inlines the listed `interface_files` in full,
- inlines the `reference_*` excerpt if the ticket has one,
- inlines the crate's `.agents/AGENT.md`,
- lists the `verify_commands` to run after the change.

### 3. Run the agent, scoped

Open a fresh session (new chat, or `cd <crate>` for Claude Code) and paste
the generated context pack as the first message, followed by the actual
instruction (the ticket's "Task" section already has good wording — paste
that too, or just say "work through this ticket").

Keep the session to **one ticket**. Don't let it wander into other crates —
if it needs to touch another crate, that's a sign the ticket boundary was
drawn wrong; split it and note that in `TICKETS_INDEX.md`.

### 4. Verify with scoped commands first

Every ticket lists `verify_commands`. These are deliberately crate-scoped
(`cargo check -p csv-adapters-solana`, not `cargo build --workspace`).
Cheap, fast, and enough signal for iteration. Save the workspace-wide
`AGENTS.md` commands (full build/test/fmt/clippy/architecture constitution)
for batch verification after a few tickets land.

### 5. Capture the pattern (Theme-A tickets especially)

The six chain adapters implement the same traits
(`csv-protocol/src/chain_adapter_traits.rs`). Most of Theme A is the *same*
kind of gap (proof validation / balance query / seal registry check)
repeated six times. The first adapter you fix for a given gap is the
**reference ticket**. Write `pattern_notes/<reference-ID>.md` (template
provided) describing what changed and why. The next five adapter tickets
for the same gap then only need: their own stub + the pattern note + their
own trait impl — not a full re-derivation of protocol semantics.

### 6. Model selection

- Default: Sonnet, for everything not flagged otherwise.
- `security_critical: true` tickets (signature derivation, BLS/Merkle
  verification, replay/finality logic) — use Opus, and budget for a second
  adversarial-review pass per AGENT.md §5.3 even after tests pass.
- The repo-wide "enumerate occurrences" scouting step is handled by
  `generate_context_pack.py` + `rg`, so you don't need a separate
  cheap-model "scout" agent — the script *is* the scout.

## Files in this directory

- `TICKET_TEMPLATE.md` — copy this to create a new ticket.
- `PATTERN_NOTE_TEMPLATE.md` — copy this after closing a "reference" ticket
  for a repeated pattern.
- `generate_context_pack.py` — the context-pack builder (uses `rg`, falls
  back to `grep` if `ripgrep` isn't installed).
- `context_packs/` — generated output, gitignore-able. Safe to delete and
  regenerate at any time.
- `pattern_notes/` — short, durable notes describing solved patterns, kept
  in version control (these are cheap and very high value for future
  sessions).

## What this does *not* replace

- The per-crate `.agents/AGENT.md` security invariants — still load these,
  every time, for every ticket. They're ~1.2k tokens; that's noise compared
  to the savings above.
- The architecture constitution tests (`csv-architecture`,
  `dep_graph_constitution.rs`, `architecture.yml`). Those stay the
  deterministic backstop — run them in batches, not per-ticket.
- Human review of anything touching `csv-protocol/src/signature.rs`,
  finality, replay, or proof verification. Context-scoping makes iteration
  cheaper; it does not make security review optional.
