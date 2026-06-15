# AI Agent Workflow: Context-Scoped Development

This workflow exists for one reason: **never load the whole repository into an AI session again**. Your repomix snapshot is roughly a million-token context blob. The project should instead be developed through small, security-aware tickets that each generate a minimal context pack.

The workflow is intentionally conservative because this is a cross-chain protocol. It preserves the existing `AGENTS.md` / `.agents/AGENT.md` rules, but moves discovery and context assembly out of the model and into deterministic local scripts.

## What is included

```text
development/
  agent-workflow/
    README.md
    TICKET_TEMPLATE.md
    PATTERN_NOTE_TEMPLATE.md
    generate_context_pack.py
    context_packs/
    pattern_notes/
  tickets/
    TICKETS_INDEX.md
    *.md
```

## Core loop

```text
pick one ticket
  -> generate one context pack
  -> paste only that context pack into an agent session
  -> edit only the ticket's target files
  -> run crate-scoped checks
  -> write a pattern note if the fix repeats across adapters
  -> mark the ticket done
```

## First run

From the repository root:

```bash
python3 development/agent-workflow/generate_context_pack.py \
  development/tickets/F-CODEC-001.md
```

Then open:

```text
development/agent-workflow/context_packs/F-CODEC-001_context.md
```

Paste that file into a fresh agent session. `F-CODEC-001` is a deliberately small warm-up ticket.

## Why this works for this codebase

This repo already has strong architecture boundaries: chain adapters live under `csv-adapters/`, CLI and SDK are separate, protocol invariants live under `csv-protocol/`, and the architecture tests enforce dependency direction. A ticket usually needs only:

1. The one file being changed.
2. The relevant trait/interface file.
3. The crate or root agent rules.
4. A sibling implementation if this is a repeated adapter pattern.
5. A repo-wide grep manifest for equivalent placeholders.

That is normally 10k-60k tokens instead of 900k-1M tokens.

## Ticket hygiene

Keep tickets atomic. If a ticket wants to edit three or more production files, split it unless the files are inseparable.

For security-critical tickets, especially signatures, proof validation, replay, finality, and minting, use a stronger model and run a second adversarial review pass before merging. The generator marks `security_critical: true` tickets in the context pack, but it cannot do the review for you.

## Pattern notes

Most adapter fixes repeat across Sui, Aptos, Ethereum, Bitcoin, Solana, and Celestia. The first implementation of a repeated pattern should produce a short note in:

```text
development/agent-workflow/pattern_notes/<ticket-id>.md
```

Use `PATTERN_NOTE_TEMPLATE.md`. The next adapter ticket should include that note instead of reloading another full implementation.

## Verification strategy

Per-ticket sessions should run scoped checks, for example:

```bash
cargo check -p csv-sui
cargo test -p csv-codec
```

After a batch of related tickets, run full workspace checks:

```bash
CXXFLAGS="-include cstdint" cargo build --workspace --all-features
CXXFLAGS="-include cstdint" cargo test --workspace --all-features
cargo fmt --all -- --check
cargo clippy --workspace --all-features -- -D warnings
cargo test -p csv-architecture
```

Do not ask an agent to remember architecture rules that deterministic tests can enforce.

## Important note about REMAINING_TASKS.md

Your uploaded project shows that parts of `development/REMAINING_TASKS.md` are stale relative to the current source tree. For example, some items that appeared open in the earlier list now look implemented in the repomix snapshot. The tickets in this package are based on **current grep-visible placeholder/stub markers** from the uploaded full project, and every generated context pack re-finds the live source snippets by literal pattern.

Line numbers are useful hints, but the current source is authoritative.
