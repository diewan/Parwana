---
id: DEV-WORKFLOW-001
title: "Create ticket index and context-pack discipline"
theme: "Development Workflow"
crate: "development"
priority: P1
security_critical: false
model_hint: sonnet
status: open
context_radius: 25
agent_md: "AGENTS.md"
target_file: "development/tickets/TICKETS_INDEX.md"
target_patterns:
  - "CSV CLI Testnet MVP"
target_file_2: "development/agent-workflow/generate_context_pack.py"
target_patterns_2:
  - "parse_frontmatter"
interface_files:
  - "development/agent-workflow/TICKET_TEMPLATE.md"
  - "development/agent-workflow/PATTERN_NOTE_TEMPLATE.md"
reference_crate: "development/agent-workflow"
reference_file: "development/agent-workflow/README.md"
reference_patterns:
  - "Context-Scoped Development"
verify_commands:
  - "python3 development/agent-workflow/generate_context_pack.py development/tickets/CLI-TRUTH-001.md"
  - "python3 development/agent-workflow/generate_context_pack.py development/tickets/PROOF-ARTIFACT-001.md"
forbidden_patterns:
  - "whole repo"
  - "make CLI work"
contract_files:
  - "development/tickets/TICKETS_INDEX.md"
cross_boundary_check: false
---

## Problem

The new CLI-first phase needs tickets that are small enough for AI agents to finish without architectural invention.

## Why it matters

Security-critical protocol work should be context-scoped and reviewable. Agents should not receive the whole repo when a target file, interface file, and reference pattern are enough.

## Task

Maintain `development/tickets/TICKETS_INDEX.md` and ensure every ticket includes:

```text
target_file
interface_files
reference_file
target_patterns
forbidden_patterns
verify_commands
security_critical
context_radius
cross_boundary_check
```

## Acceptance criteria

- [ ] Every ticket generates a context pack under 60k tokens where possible.
- [ ] Adapter tickets include sibling/reference implementation only when needed.
- [ ] Security-critical tickets require adversarial review.
- [ ] Pattern notes are produced for repeated adapter work.
- [ ] No agent receives the whole repo.
