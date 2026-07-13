---
id: REPOSPLIT-CONFORMANCE-006
title: "Create versioned cross-boundary golden vectors and adapter conformance tests"
theme: multi-repo-conformance
crate: csv-testkit
priority: P1
security_critical: true
model_hint: opus
status: open
context_radius: 35
agent_md: .agents/AGENT.md
target_file: csv-testkit/src/fixtures.rs
target_patterns:
  - "fixture"
target_file_2: csv-testkit/src/adversarial.rs
target_patterns_2:
  - "replay"
  - "proof"
interface_files:
  - csv-codec/src/lib.rs
  - csv-proof/src/lib.rs
  - csv-adapters/csv-adapter-core/src/lib.rs
reference_crate: csv-protocol
reference_file: csv-protocol/tests/golden_vectors.rs
reference_patterns:
  - "golden"
verify_commands:
  - "cargo test -p csv-codec -p csv-hash -p csv-proof -p csv-verifier -p csv-testkit"
  - "CXXFLAGS=\"-include cstdint\" cargo test -p csv-runtime"
forbidden_patterns:
  - "fake proof"
  - "mock signature"
  - "vec![0u8;"
  - "Ok(true)"
contract_files:
  - csv-contracts/ethereum/contracts/src/CSVSeal.sol
  - csv-contracts/solana/contracts/idl/csv_seal.json
cross_boundary_check: true
---

## Problem

Existing tests are extensive but are primarily workspace-local. Independently
released core, adapters, runtime, and contracts need immutable artifacts that
prove they agree on canonical bytes, hashes, replay IDs, proof semantics,
events, and failure behavior.

## Why it matters

Cross-repository drift in one byte, domain tag, finality field, or replay input
can cause rejection divergence or unsafe materialization. Positive-only vectors
would miss the fail-closed obligations central to this protocol.

## Task

Define a versioned, deterministic golden corpus and a reusable adapter
conformance harness. Make the artifacts consumable without relative filesystem
paths. Cover positive and adversarial cases and define immutable release rules.

## Acceptance criteria

- [ ] Golden vectors cover canonical CBOR, typed hashes, proof bundles, replay IDs, authorization payloads, and canonical contract events.
- [ ] Every adapter runs the same chain-neutral conformance contract.
- [ ] Malformed proof, forged authorization, replay/double-use, insufficient finality, and crash-resume cases are included.
- [ ] Released vectors are immutable; semantic changes create a new corpus version.
- [ ] Fixture regeneration is deterministic and produces a reviewable diff.
- [ ] N and N-1 supported component combinations can consume the corpus in CI.
- [ ] No fixture uses fabricated production evidence as a positive case.

## Notes

Test-only mocks remain acceptable when clearly scoped, but golden positive
vectors must represent cryptographically valid protocol artifacts.
