---
id: REPOSPLIT-READINESS-007
title: "Complete TRM-HARDEN security evidence and multichain testnet matrix"
theme: multi-repo-release-readiness
crate: csv-runtime
priority: P0
security_critical: true
model_hint: opus
status: open
context_radius: 40
agent_md: .agents/AGENT.md
target_file: csv-docs/RELEASE_READINESS_TRM_HARDEN_001.md
target_patterns:
  - "Required Gates"
  - "End-to-End Matrix"
  - "Stop-Ship Conditions"
target_file_2: csv-docs/runbooks/OPERATOR_ROLLOUT_MULTICHAIN.md
target_patterns_2:
  - "evidence"
interface_files:
  - csv-runtime/README.md
reference_crate: csv-testkit
reference_file: csv-testkit/src/adversarial.rs
reference_patterns:
  - "replay"
verify_commands:
  - "CXXFLAGS=\"-include cstdint\" cargo test --workspace --all-features"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-runtime"
forbidden_patterns:
  - "manual observation only"
  - "assumed passing"
  - "warning instead of error"
contract_files:
  - ""
cross_boundary_check: true
---

## Problem

The TRM-HARDEN release-readiness checklist still contains unchecked replay,
authorization, settlement, recovery, event-conformance, observability, and
testnet gates. Splitting repositories before retaining this evidence would make
root-cause analysis and coordinated fixes harder.

## Why it matters

These are explicit stop-ship invariants: no duplicate mint, no replay, no
premature settlement, no remint on recovery, and no materialization without
verified inclusion and finality.

## Task

Execute every automated and testnet gate in the readiness checklist. Store a
dated evidence bundle containing transfer identifiers, source and destination
transactions, settlement evidence, replay attempts, logs/metrics, toolchain
versions, and exact commands. Link every checkbox to retained evidence and an
automated regression test where possible.

## Acceptance criteria

- [ ] Every checklist item has linked, dated evidence.
- [ ] The required cross-chain testnet matrix is complete or explicitly blocked with a fail-closed release decision.
- [ ] Duplicate sanad ID, nullifier, and lock event ID attempts are rejected before a second mint.
- [ ] Forged/premature settlement is rejected before source payout.
- [ ] Resume after `MintSubmitted` confirms rather than rebroadcasts.
- [ ] Operator signals cover every required success and rejection event.
- [ ] Evidence contains no secrets, private keys, mnemonics, or reusable credentials.
- [ ] All stop-ship conditions are closed before marking the ticket done.

## Notes

This ticket may coordinate several test runs, but it must not weaken a test or
convert an error to a warning to complete the matrix.
