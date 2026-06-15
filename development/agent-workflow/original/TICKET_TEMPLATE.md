<!--
TICKET TEMPLATE
================
Copy this file to development/tickets/<ID>.md and fill it in.

The YAML frontmatter is machine-readable: generate_context_pack.py parses it
to build the context bundle. Keep it flat (scalars and simple string lists
only — no nested maps). The Markdown body below the frontmatter is for
humans and for the agent; write it like you'd write a real ticket.

Field reference:

  id                Unique ticket ID. Convention: <AREA>-<NNN>, where AREA
                    matches the crate/theme (e.g. A-SOLANA, D-PROTO, E-WALLET).

  title             One line, human-readable.

  theme             Matches REMAINING_TASKS.md theme letter (A-G), or "P1"
                    for the priority-1 blockers, or "MISC" for M/L items.

  crate             Workspace crate this ticket lives in, e.g.
                    csv-adapters/csv-solana. Used to pick the default
                    AGENT.md and to scope verify_commands.

  priority          P1 | P2 | P3 (matches REMAINING_TASKS.md priority bands).

  security_critical true | false. If true: use Opus, do a second adversarial
                    review pass (AGENT.md §5.3), and don't batch this with
                    other tickets before full verification.

  model_hint        sonnet | opus. Default sonnet. Set opus for
                    security_critical tickets or anything touching
                    signature/finality/replay/proof verification.

  status            open | in_progress | done | blocked.

  target_file       The single primary file this ticket edits. If a ticket
                    genuinely needs 2 files, list the second under
                    target_file_2 (same shape). If it needs 3+, the ticket
                    is too big — split it.

  target_patterns   List of literal strings (matched with `rg -F`) that
                    locate the stub(s) in target_file. These are the
                    "For now" / "TODO" / "Simplified" markers from
                    REMAINING_TASKS.md. Line numbers drift; strings don't.

  interface_files   List of file paths to inline in FULL — the trait/type
                    definitions the new code must satisfy. Keep this list
                    short (1-3 files). Good candidates:
                    csv-protocol/src/chain_adapter_traits.rs,
                    csv-protocol/src/finality/abstraction.rs,
                    csv-hash/src/... (specific hash/commitment types),
                    csv-protocol/src/verification_levels.rs.

  reference_crate   (optional) For "solve once, replicate across adapters"
                    tickets: the crate that already implements this pattern
                    correctly.

  reference_file    (optional) The specific file in reference_crate.

  reference_patterns (optional) List of literal strings locating the
                    relevant function(s) in reference_file.

  context_radius    Lines of context around each matched pattern to include.
                    20-30 is usually right. Bump for dense code.

  agent_md          Path to the AGENT.md to inline. Default:
                    <crate>/.agents/AGENT.md, or csv-adapters/.agents/AGENT.md
                    for anything under csv-adapters/.

  verify_commands   List of shell commands to run after the change, in
                    order. Scope these to the crate (`-p <crate-name>`),
                    not the workspace. Always include the relevant
                    constitution test if one exists for this area.
-->
---
id: TEMPLATE-000
title: ""
theme: ""
crate: ""
priority: P2
security_critical: false
model_hint: sonnet
status: open
target_file: ""
target_patterns:
  - ""
interface_files:
  - ""
reference_crate: ""
reference_file: ""
reference_patterns:
  - ""
context_radius: 25
agent_md: ""
verify_commands:
  - ""
---

## Problem

What's wrong, in plain language. Quote the stub/placeholder comment(s) from
REMAINING_TASKS.md verbatim if useful, but note that the *current* source is
authoritative — the generated context pack pulls live snippets.

## Why it matters

Tie this back to the invariant(s) in AGENT.md it currently violates (e.g.
"No placeholder verification", "No mint without verified inclusion +
verified finality"). If it doesn't violate a numbered invariant, say so —
some Theme-F/G items are genuinely low-stakes cleanup.

## Task

Concrete, scoped instruction for the agent. Reference the
`interface_files` and `reference_*` fields by name so the agent knows
they're already in its context — don't re-paste them here.

## Acceptance criteria

- [ ] Stub/placeholder removed (no `TODO`, `For now`, `Simplified`, etc.
      remaining for this specific item)
- [ ] Matches the trait contract in `interface_files`
- [ ] New/updated test: positive case
- [ ] New/updated test: malformed/negative case (if this is a verification
      path — required per AGENT.md §6)
- [ ] `verify_commands` all pass
- [ ] No new occurrences of the forbidden patterns in AGENT.md §2 introduced

## Notes / open questions

Anything the ticket-writer wasn't sure about — cross-chain quirks,
ambiguity in the spec, etc. The agent should flag rather than guess on
anything listed here.
