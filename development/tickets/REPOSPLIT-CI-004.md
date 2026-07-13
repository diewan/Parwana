---
id: REPOSPLIT-CI-004
title: "Add the complete Rust workspace release CI matrix"
theme: multi-repo-ci
crate: csv-architecture
priority: P1
security_critical: false
model_hint: sonnet
status: open
context_radius: 30
agent_md: .agents/AGENT.md
target_file: .github/workflows/architecture.yml
target_patterns:
  - "jobs:"
  - "Check release metadata and package contents"
target_file_2: scripts/check-release.sh
target_patterns_2:
  - "cargo package"
interface_files:
  - Cargo.toml
  - .config/nextest.toml
reference_crate: csv-architecture
reference_file: csv-architecture/tests/dep_graph_constitution.rs
reference_patterns:
  - "workspace_release_metadata_is_coherent"
verify_commands:
  - "cargo fmt --all -- --check"
  - "CXXFLAGS=\"-include cstdint\" cargo build --workspace --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test --workspace --all-features"
  - "cargo test --workspace --doc"
  - "cargo clippy --workspace --all-features -- -D warnings"
  - "scripts/check-release.sh"
forbidden_patterns:
  - "continue-on-error: true"
  - "|| true"
contract_files:
  - ""
cross_boundary_check: true
---

## Problem

CI enforces architecture, formal models, and package listing, but it does not
yet run the complete advertised Rust release matrix. A prospective repository
could therefore be extracted while an all-feature build, doctest, format,
Clippy, WASM, or dependency-policy failure remains undiscovered.

## Why it matters

Repository boundaries remove the protection of one workspace build. Each
future repository needs a fail-closed baseline before extraction.

## Task

Add partitioned CI jobs for the complete Rust quality matrix. Preserve the
existing architecture and formal jobs. Use caching and concurrency controls
without suppressing failures. Make the supported and unsupported WASM feature
combinations explicit.

## Acceptance criteria

- [ ] Workspace build and tests run with all features.
- [ ] Doctests, formatting, and Clippy with warnings denied run in CI.
- [ ] Supported WASM/no-default-feature checks run and unsupported combinations are asserted deliberately.
- [ ] Package checks and dependency/security policy checks are required jobs.
- [ ] Ignored RPC integration tests have a documented separate execution policy.
- [ ] Jobs expose reproducible commands and useful failure diagnostics.
- [ ] No mandatory gate uses `continue-on-error` or masks failure.

## Notes

Contract toolchains receive their own extraction-oriented ticket; do not make
this Rust CI ticket depend on installing every chain contract CLI.
