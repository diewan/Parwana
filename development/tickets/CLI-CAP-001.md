---
id: CLI-CAP-001
title: "Chain capability and readiness matrix"
theme: "CLI Honest Mode"
crate: "csv-cli"
priority: P0
security_critical: true
model_hint: opus
status: open
context_radius: 35
agent_md: "AGENTS.md"
target_file: "csv-cli/src/commands/chain.rs"
target_patterns:
  - "Readiness"
target_file_2: "csv-protocol/src/chain_adapter_traits.rs"
target_patterns_2:
  - "ChainReadiness"
interface_files:
  - "csv-cli/src/commands/chain_management.rs"
  - "csv-sdk/src/runtime.rs"
  - "csv-protocol/src/finality/capabilities.rs"
reference_crate: "csv-adapters"
reference_file: "csv-adapters/csv-bitcoin/src/ops.rs"
reference_patterns:
  - "check_readiness"
verify_commands:
  - "cargo test -p csv-cli --test integration_tests"
  - "cargo test -p csv-protocol"
forbidden_patterns:
  - "placeholder success"
  - "Ok(true)"
  - "unsupported but yes"
contract_files:
  - "csv-cli/src/commands/chain.rs"
  - "csv-sdk/src/runtime.rs"
  - "csv-protocol/src/chain_adapter_traits.rs"
cross_boundary_check: true
---

## Problem

Users need to know what each chain can actually do before attempting Sanad or transfer operations. Readiness exists conceptually, but the CLI does not yet expose the full capability matrix with machine-readable output.

## Why it matters

Unsupported operations must fail before state mutation. Capability gaps must be visible instead of surfacing as placeholder successes later in protocol flows.

## Task

Add:

```bash
csv chain capabilities
csv chain readiness --chain <chain> --json
```

Output the required matrix for wallet derivation, balance, seal/Sanad operations, proof build/verify, lock/mint, state/trace readers, RPC/config status, and testnet readiness.

## Acceptance criteria

- [ ] Unsupported operations return `CapabilityUnavailable`, not placeholder success.
- [ ] CLI refuses commands before execution if required capability is absent.
- [ ] Bitcoin reports no destination mint capability unless a supported mint mechanism exists.
- [ ] Contract chains report missing deployment/configuration before Sanad commands run.
- [ ] Readiness output is machine-readable with `--json`.
