---
id: REPOSPLIT-BOUNDARY-009
title: "Build virtual repository groups in isolation and rehearse history extraction"
theme: multi-repo-boundary-rehearsal
crate: csv-architecture
priority: P1
security_critical: true
model_hint: opus
status: open
context_radius: 35
agent_md: .agents/AGENT.md
target_file: Cargo.toml
target_patterns:
  - "members = ["
  - "workspace.dependencies"
target_file_2: scripts/check-release.sh
target_patterns_2:
  - "cargo metadata"
  - "cargo package"
interface_files:
  - csv-architecture/tests/dep_graph_constitution.rs
  - development/tickets/TICKETS_INDEX.md
reference_crate: csv-architecture
reference_file: .github/workflows/architecture.yml
reference_patterns:
  - "jobs:"
verify_commands:
  - "scripts/check-release.sh"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-architecture"
  - "cargo metadata --locked --format-version 1"
forbidden_patterns:
  - "git reset --hard"
  - "git push --force"
  - "unversioned artifact"
contract_files:
  - ""
cross_boundary_check: true
---

## Problem

Path-plus-version dependencies prove package metadata coherence, but normal
workspace builds still allow undeclared filesystem coupling, shared fixtures,
and atomic source changes. The proposed repository seams have not been tested
against packaged dependencies or filtered history.

## Why it matters

A physical split should reveal no new compile, test, attribution, licensing,
or security failures. Discovering those after repositories are created would
force emergency cross-repository changes.

## Task

Define virtual groups for spec, core, runtime, adapters, contracts, and tools.
In temporary CI workspaces, build each group against packaged/versioned
artifacts and only its declared files. Rehearse history extraction without
changing the canonical repository. Measure cross-group change coupling over at
least two tagged release candidates and write a go/no-go report.

## Acceptance criteria

- [ ] Each virtual group has an isolated build/test job.
- [ ] No group reads undeclared source or fixtures from another group.
- [ ] Internal dependencies resolve from packaged artifacts in the rehearsal.
- [ ] Supported N/N-1 combinations run according to the compatibility policy.
- [ ] Filtered-history rehearsal retains relevant commits, tags, licenses, authorship, and security documentation.
- [ ] Cross-group commit coupling and required coordinated releases are measured.
- [ ] A written report gives a go/no-go decision for the contracts pilot.

## Notes

Blocked by `REPOSPLIT-PORTS-001` through `REPOSPLIT-GOVERNANCE-008`. Temporary
rehearsal repositories must not be pushed to public hosting.
