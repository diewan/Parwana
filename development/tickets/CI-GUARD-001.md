---
id: CI-GUARD-001
title: "Enforce security grep rules in CI"
theme: "Architecture Enforcement"
crate: "csv-architecture"
priority: P1
security_critical: true
model_hint: sonnet
status: open
context_radius: 30
agent_md: "AGENTS.md"
target_file: "csv-architecture/tests/architecture_guard.rs"
target_patterns:
  - "csv-core"
target_file_2: ".github/workflows/architecture.yml"
target_patterns_2:
  - "architecture"
interface_files:
  - "deny.toml"
  - "scripts/dev.sh"
reference_crate: "development"
reference_file: "development/agent-workflow/TICKET_TEMPLATE.md"
reference_patterns:
  - "forbidden_patterns"
verify_commands:
  - "cargo test -p csv-architecture"
  - "cargo clippy --workspace --all-features -- -D warnings"
forbidden_patterns:
  - "todo!"
  - "unimplemented!"
  - "panic!"
  - "unwrap()"
  - "expect()"
  - "Hash::new([0u8; 32])"
  - "serde_json"
contract_files:
  - "csv-architecture/tests/architecture_guard.rs"
  - ".github/workflows/architecture.yml"
cross_boundary_check: true
---

## Problem

Security-sensitive placeholder patterns can be reintroduced unless CI blocks them in production code with narrow reviewed exceptions.

## Why it matters

Verification, finality, replay, and minting paths must fail closed by construction.

## Task

Add CI and architecture tests for forbidden production patterns: `todo!`, `unimplemented!`, `panic!`, `unwrap()`, `expect()`, placeholder `Ok(true)`/`Ok(())` validation, zero hashes, empty proof vectors, production mock fallback, direct adapter imports from CLI, direct mint paths outside `TransferCoordinator`, and `serde_json` in canonical hashing paths.

## Acceptance criteria

- [ ] CI fails on forbidden patterns outside approved directories.
- [ ] Exceptions are explicit, reviewed, and narrow.
- [ ] Architecture tests confirm CLI does not import chain adapters.
- [ ] Architecture tests confirm runtime does not import concrete adapters directly.
- [ ] Compile-fail tests are preferred where possible.
