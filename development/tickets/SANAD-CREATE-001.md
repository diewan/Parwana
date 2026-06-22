---
id: SANAD-CREATE-001
title: "Canonical Sanad creation request"
theme: "Same-chain Sanad MVP"
crate: "csv-cli"
priority: P0
security_critical: true
model_hint: opus
status: open
context_radius: 35
agent_md: "AGENTS.md"
target_file: "csv-cli/src/commands/sanads.rs"
target_patterns:
  - "Hash::new([0u8; 32])"
target_file_2: "csv-sdk/src/sanads.rs"
target_patterns_2:
  - "create"
interface_files:
  - "csv-sdk/src/client.rs"
  - "csv-protocol/src/sanad.rs"
reference_crate: "csv-sdk"
reference_file: "csv-sdk/src/runtime.rs"
reference_patterns:
  - "check_readiness"
verify_commands:
  - "cargo test -p csv-cli --test integration_tests"
  - "cargo test -p csv-sdk"
forbidden_patterns:
  - "Hash::new([0u8; 32])"
  - "--skip-publish"
  - "real active Sanad"
contract_files:
  - "csv-cli/src/commands/sanads.rs"
  - "csv-sdk/src/sanads.rs"
  - "csv-protocol/src/sanad.rs"
cross_boundary_check: true
---

## Problem

`csv sanad create` still contains chain-specific business logic and all-zero hash defaults for missing descriptor fields.

## Why it matters

All-zero hashes must not mean missing. A real Sanad must be anchored by runtime/adapter execution, not by CLI synthesis.

## Task

Introduce a typed request:

```rust
CreateSanadRequest {
    chain,
    owner,
    value,
    content_descriptor,
    funding_selector,
    publish_policy,
}
```

The CLI builds the request. SDK/runtime executes it. Missing optional fields must be represented explicitly, not as zero hashes.

## Acceptance criteria

- [ ] No all-zero hash means missing.
- [ ] `--skip-publish` cannot produce a real active Sanad; at most it creates a local unsigned draft/export.
- [ ] Creation returns canonical Sanad ID, seal reference, owner, commitment, anchor tx, block height, and finality status.
- [ ] Tests prove missing required descriptor fields fail closed.
