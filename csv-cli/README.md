# csv-cli

CLI tool for the CSV Protocol — cross-chain Sanads, proofs, and seal management.

## Overview

The CLI is a **stateless client** that delegates all protocol authority to `csv-runtime`. It holds NO protocol state (leases, transfers, replay registry). All lease management, transfer execution, and replay protection is handled exclusively by the runtime.

## Architecture

```
csv-cli (stateless)
  └── csv-runtime (holds all protocol authority)
        ├── csv-protocol
        └── csv-adapters (registered via AdapterRegistry)
```

## Commands

- `csv seals` — Manage seal operations
- `csv proofs` — Create and verify proofs
- `csv sanads` — Manage Sanad documents
- `csv wallet` — Wallet operations
- `csv cross-chain` — Cross-chain transfer management (delegates to runtime)
- `csv validate` — Validate protocol objects

## Design Principles

- **Stateless**: CLI holds no protocol authority state
- **Delegation**: All protocol operations delegated to csv-runtime
- **No direct chain access**: CLI must not import chain adapters directly
- **Crash-safe**: Runtime provides crash-safe recovery via execution journal

## Dependencies

- `csv-runtime`: Runtime orchestration (holds all protocol authority)
- `csv-sdk`: SDK facade for operations
- `csv-keys`: Key management
- `clap`: CLI argument parsing

## License

MIT OR Apache-2.0
