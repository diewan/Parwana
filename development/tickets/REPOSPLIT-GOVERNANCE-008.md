---
id: REPOSPLIT-GOVERNANCE-008
title: "Define repository ownership and coordinated security release governance"
theme: multi-repo-governance
crate: csv-protocol
priority: P1
security_critical: true
model_hint: opus
status: open
context_radius: 30
agent_md: .agents/AGENT.md
target_file: csv-docs/PROTOCOL_CONSTITUTION.md
target_patterns:
  - "Governance"
  - "Constitution"
target_file_2: csv-docs/THREAT_MODEL.md
target_patterns_2:
  - "threat"
interface_files:
  - AGENTS.md
  - .agents/AGENT.md
reference_crate: csv-protocol
reference_file: README.md
reference_patterns:
  - "Security"
verify_commands:
  - "cargo test --workspace --doc"
forbidden_patterns:
  - "TBD owner"
  - "best effort"
contract_files:
  - ""
cross_boundary_check: true
---

## Problem

A monorepo permits one atomic security change. Multiple repositories require
explicit ownership, review authority, embargo coordination, dependency update
service levels, and emergency publication order. Those responsibilities are
not yet defined for the proposed repository groups.

## Why it matters

A verifier or contract fix must not become public while dependent adapters or
runtime releases remain unavailable. Repository ownership is therefore part of
the security model, not merely project administration.

## Task

Document accountable ownership and the coordinated change/release process for
spec, core, runtime, adapters, contracts, and tools. Include normal breaking
changes, embargoed vulnerabilities, emergency patches, supported version
lifetimes, dependency update SLAs, reviewer requirements, maintainer departure,
and signing-key rotation.

## Acceptance criteria

- [ ] Every proposed repository group has named accountable owners and backups.
- [ ] Required reviewers are defined for protocol, cryptography, runtime, adapter, contract, and release changes.
- [ ] Embargoed fixes can be prepared and released without a public dependency gap.
- [ ] Supported-version lifetimes and dependency update SLAs are defined.
- [ ] Branch protection, tag protection, and release authority are documented.
- [ ] Maintainer departure and signing-key rotation procedures exist.
- [ ] Ownership of normative fixtures and generated bindings is unambiguous.

## Notes

Do not create repositories as part of this ticket. This ticket defines the
authority model that must exist before extraction.
