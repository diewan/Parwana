---
id: REPOSPLIT-RELEASE-005
title: "Establish tagged crate release automation and artifact provenance"
theme: multi-repo-release
crate: csv-protocol
priority: P1
security_critical: true
model_hint: opus
status: open
context_radius: 35
agent_md: .agents/AGENT.md
target_file: scripts/publish.sh
target_patterns:
  - "cargo publish"
  - "dry-run"
target_file_2: scripts/check-release.sh
target_patterns_2:
  - "Release metadata"
interface_files:
  - Cargo.toml
  - csv-runtime/CHANGELOG.md
  - csv-sdk/CHANGELOG.md
reference_crate: csv-protocol
reference_file: csv-protocol/Cargo.toml
reference_patterns:
  - "version.workspace"
verify_commands:
  - "scripts/check-release.sh"
  - "cargo metadata --locked --format-version 1"
forbidden_patterns:
  - "--no-verify"
  - "git push --force"
  - "cargo publish --allow-dirty"
contract_files:
  - ""
cross_boundary_check: true
---

## Problem

The workspace can validate package contents and dependency versions, but it has
no demonstrated tagged release flow, dependency-ordered publication,
SemVer/API gate, artifact attestation, or rollback/yank runbook. A source split
would make every missing release control operationally expensive.

## Why it matters

Security fixes may span core, runtime, adapters, bindings, and tools. Releases
must be ordered, reproducible, traceable to reviewed commits, and capable of
coordinated embargoed publication.

## Task

Implement a dry-run-first release workflow for publishable Rust crates. Compute
the internal publish order, enforce clean tested commits, check API compatibility,
generate or validate changelogs, create tags/releases, and record artifact
provenance. Document failure recovery and crate yanking.

## Acceptance criteria

- [ ] A dry run packages every publishable crate in dependency order without sibling-only resolution.
- [ ] Private/test-only crates are excluded explicitly.
- [ ] Release automation refuses dirty, untested, or incompatible commits.
- [ ] Crate versions, changelogs, Git tags, and release artifacts agree.
- [ ] Artifact checksums and build provenance are retained.
- [ ] Rollback, yank, and emergency coordinated-release procedures are documented.
- [ ] No command bypasses Cargo verification or force-pushes release history.

## Notes

Actual publication must remain an explicit maintainer action until the dry-run
workflow has succeeded on at least one release candidate.
