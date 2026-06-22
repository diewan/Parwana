---
id: CLI-TRUTH-001
title: "Define the CLI Golden Path Gauntlet"
theme: "CLI Testnet MVP"
crate: "csv-cli"
priority: P0
security_critical: true
model_hint: opus
status: open
context_radius: 35
agent_md: "AGENTS.md"
target_file: "csv-cli/tests/integration_tests.rs"
target_patterns:
  - "Integration tests for csv-cli commands"
target_file_2: "csv-examples/cli-tutorial/quick-start.sh"
target_patterns_2:
  - "CSV Protocol CLI - Quick Start"
interface_files:
  - "csv-examples/cli-tutorial/cross-chain-transfer.sh"
  - "development/tickets/TICKETS_INDEX.md"
reference_crate: "development/agent-workflow"
reference_file: "development/agent-workflow/TICKET_TEMPLATE.md"
reference_patterns:
  - "security_critical"
verify_commands:
  - "cargo test -p csv-cli --test integration_tests cli_golden_path_gauntlet_contract"
forbidden_patterns:
  - "skip publish"
  - "placeholder success"
  - "mock production"
  - "local canonical"
contract_files:
  - "csv-examples/cli-tutorial/quick-start.sh"
  - "csv-examples/cli-tutorial/cross-chain-transfer.sh"
cross_boundary_check: true
---

## Problem

The CLI MVP path is not expressed as a single deterministic gauntlet. Existing tutorials demonstrate commands, but they do not yet form an executable product contract for wallet initialization, Sanad creation, canonical proof handling, transfer status, replay rejection, malformed proof rejection, and trace visibility.

## Why it matters

The CLI must become the reference product surface. Without a golden-path gauntlet, implementation can drift into demos that print local guesses or tolerate incomplete protocol behavior.

## Task

Add a failing-first CLI gauntlet contract covering:

```text
wallet init
wallet generate bitcoin
wallet generate ethereum
wallet balance
sanad create
sanad state
proof generate
proof verify
cross-chain transfer
cross-chain status
sanad trace
replay attempt
malformed proof attempt
```

The first version may use deterministic test fixtures under tests or testkit. It must not add fake production behavior or production mock fallbacks.

## Acceptance criteria

- [ ] The gauntlet can be run by one documented command.
- [ ] Failing steps identify the exact missing protocol capability.
- [ ] No production code is weakened to make the gauntlet pass.
- [ ] Tutorial scripts point at the same flow and do not describe local guesses as protocol truth.
- [ ] The gauntlet is referenced from `TICKETS_INDEX.md` as the product definition of CLI MVP.
