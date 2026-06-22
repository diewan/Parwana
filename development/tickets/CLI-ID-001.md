---
id: CLI-ID-001
title: "Canonical Sanad ID handling"
theme: "CLI Honest Mode"
crate: "csv-cli"
priority: P0
security_critical: true
model_hint: sonnet
status: open
context_radius: 30
agent_md: "AGENTS.md"
target_file: "csv-hash/src/sanad.rs"
target_patterns:
  - "SanadId"
target_file_2: "csv-cli/src/commands/sanads.rs"
target_patterns_2:
  - "hex::encode(sanad_id.as_bytes())"
interface_files:
  - "csv-cli/src/commands/proofs.rs"
  - "csv-cli/src/commands/cross_chain/transfer.rs"
  - "csv-sdk/src/runtime.rs"
  - "csv-sdk/src/sanads.rs"
reference_crate: "csv-hash"
reference_file: "csv-hash/src/seal.rs"
reference_patterns:
  - "from"
verify_commands:
  - "cargo test -p csv-hash sanad_id"
  - "cargo test -p csv-cli --test integration_tests"
forbidden_patterns:
  - "hex::encode(sanad_id.as_bytes())"
  - "as_bytes()).to_vec()"
  - "ASCII"
contract_files:
  - "csv-cli/src/commands/sanads.rs"
  - "csv-cli/src/commands/proofs.rs"
  - "csv-cli/src/commands/cross_chain/transfer.rs"
cross_boundary_check: true
---

## Problem

Sanad IDs are not parsed and displayed consistently. Some paths risk treating the displayed hex string as bytes and then hex-encoding those ASCII bytes.

## Why it matters

Identifier drift breaks replay protection, proof binding, transfer lookup, and user trust in CLI output.

## Task

Create or reuse one parser:

```rust
parse_sanad_id_hex(input: &str) -> Result<SanadId>
```

Use it from create/show/consume/proof/transfer/status paths. Accept `0x` and non-`0x` forms consistently.

## Acceptance criteria

- [ ] Same input Sanad ID resolves identically across create/show/consume/proof/transfer/status.
- [ ] Invalid length fails.
- [ ] Non-hex input fails.
- [ ] `0x` and non-`0x` forms are accepted consistently.
- [ ] Tests cover malformed IDs and ASCII re-encoding regression.
