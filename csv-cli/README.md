# csv-cli

CLI tool for the CSV Protocol — cross-chain Sanads, proofs, and seal management.

## Design

The CLI is a **stateless client** that delegates all protocol authority to `csv-runtime`. It holds NO protocol state (leases, transfers, replay registry). All lease management, transfer execution, and replay protection is handled exclusively by the runtime.

## Commands

- `csv seals` — Manage seal operations
- `csv proofs` — Create and verify proofs
- `csv sanads` — Manage Sanad documents
- `csv wallet` — Wallet operations
- `csv cross-chain` — Cross-chain transfer management (delegates to runtime)
- `csv validate` — Validate protocol objects

## License

MIT OR Apache-2.0
