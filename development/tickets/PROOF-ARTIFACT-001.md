---
id: PROOF-ARTIFACT-001
title: "Replace lossy CLI ProofOutput"
theme: "Canonical Proofs"
crate: "csv-cli"
priority: P0
security_critical: true
model_hint: opus
status: open
context_radius: 35
agent_md: "AGENTS.md"
target_file: "csv-cli/src/commands/proofs.rs"
target_patterns:
  - "struct ProofOutput"
target_file_2: "csv-codec/src/lib.rs"
target_patterns_2:
  - "canonical"
interface_files:
  - "csv-sdk/src/runtime.rs"
  - "csv-protocol/src/proof_taxonomy.rs"
  - "csv-proof/src/lib.rs"
reference_crate: "csv-codec"
reference_file: "csv-codec/src/lib.rs"
reference_patterns:
  - "CBOR"
verify_commands:
  - "cargo test -p csv-cli --test integration_tests"
  - "cargo test -p csv-codec"
forbidden_patterns:
  - "struct ProofOutput"
  - "vec![]"
  - "synthetic finality"
  - "JSON fallback"
contract_files:
  - "csv-cli/src/commands/proofs.rs"
  - "csv-sdk/src/runtime.rs"
cross_boundary_check: true
---

## Problem

`csv proof generate` writes a lossy summary, and `csv proof verify` reconstructs missing proof material instead of verifying canonical proof bytes.

## Why it matters

Proof verification must not insert empty signatures, synthetic finality data, anchor data, or DAG nodes. The artifact being verified must be the artifact produced.

## Task

Change proof output modes:

```text
default: canonical CBOR ProofBundle file
--json-summary: display-only summary
--hex: hex-encoded canonical CBOR
```

Verification must consume the canonical proof bundle and fail malformed or incomplete bundles.

## Acceptance criteria

- [ ] No `vec![]` signatures inserted by CLI verification.
- [ ] No synthetic finality proof during verification.
- [ ] JSON fallback is removed from security verification path or marked legacy/display-only.
- [ ] Malformed CBOR fails.
- [ ] Missing signature fails.
- [ ] Empty proof bundle fails.
- [ ] Wrong source chain fails.
- [ ] Wrong destination chain fails.
