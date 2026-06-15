<!--
Copy this file to development/tickets/<ID>.md and fill in the frontmatter.
The frontmatter is intentionally simple so generate_context_pack.py can parse
it without PyYAML.
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
context_radius: 25
agent_md: ""
target_file: ""
target_patterns:
  - ""
target_file_2: ""
target_patterns_2:
  - ""
interface_files:
  - ""
reference_crate: ""
reference_file: ""
reference_patterns:
  - ""
verify_commands:
  - ""
---

## Problem

Describe the current stub, placeholder, bypass, or incomplete behavior. Quote the exact source comment or expression if useful.

## Why it matters

Explain which invariant this affects. For security-sensitive protocol paths, mention the relevant rule from `AGENTS.md` / `.agents/AGENT.md`, such as no placeholder verification, no fabricated blockchain state, or no mint without verified inclusion plus finality.

## Task

Give the agent one concrete implementation objective. Keep this scoped to the target file(s) above.

## Acceptance criteria

- [ ] The named placeholder/stub is removed or replaced with a real fail-closed implementation.
- [ ] The implementation follows the relevant trait/interface contract.
- [ ] Production code does not introduce `todo!`, `unimplemented!`, `unwrap`, `expect`, raw hashing, fake proofs, or silent fallbacks.
- [ ] Positive test added or updated.
- [ ] Negative/adversarial test added or updated when this touches verification, signatures, replay, finality, or minting.
- [ ] All `verify_commands` pass.
- [ ] A repo-wide search confirms no equivalent production bypass remains untracked.

## Notes

Add any protocol-specific assumptions or open questions here. If the agent must not guess, say so explicitly.
