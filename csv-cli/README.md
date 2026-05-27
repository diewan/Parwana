# csv-cli

CLI tool for the CSV Protocol — cross-chain Sanads, proofs, content, trust, and runtime management.

## Overview

The CLI is a **stateless client** that delegates all protocol authority to `csv-runtime`. It holds NO protocol state (leases, transfers, replay registry). All lease management, transfer execution, and replay protection is handled exclusively by the runtime.

The CLI provides a comprehensive interface for:

- Chain configuration and status monitoring
- Wallet management (BIP-39 mnemonic, multi-chain key derivation)
- Sanad creation, transfer, and consumption
- Proof generation and verification (including cross-chain)
- Cross-chain transfer orchestration
- Seal management
- Content tree creation and selective disclosure
- Trust package management
- Runtime health monitoring and admission control
- Protocol validation and inspection
- Schema tooling
- End-to-end testing

## Architecture

```
csv-cli (stateless)
  └── csv-runtime (holds all protocol authority)
        ├── csv-protocol
        ├── csv-coordinator (per-chain execution cells)
        ├── csv-admission (pressure boundary)
        └── csv-observability (health monitoring)
```

## Commands

### Chain Management

- `csv chain list` — List all supported chains
- `csv chain status --chain <chain>` — Check chain status and RPC connectivity
- `csv chain set-rpc --chain <chain> <url>` — Set custom RPC URL
- `csv chain set-contract --chain <chain> <address>` — Set contract address
- `csv chain set-network --chain <chain> --network <dev|test|main>` — Change network

### Wallet Operations

- `csv wallet init --network test --words 12` — Initialize wallet (generates mnemonic, derives keys)
- `csv wallet import "<mnemonic>"` — Import existing wallet
- `csv wallet export` — Export mnemonic (with security warnings)
- `csv wallet generate --chain <chain>` — Generate wallet for specific chain
- `csv wallet balance --chain <chain>` — Check balance
- `csv wallet list` — List all wallet addresses
- `csv wallet private-key --chain <chain>` — View private key (use with caution)

### Sanad Operations

- `csv sanad create --chain <chain> --value <amount>` — Create a Sanad
- `csv sanad show <sanad_id>` — Show Sanad details
- `csv sanad list [--chain <chain>]` — List Sanads
- `csv sanad transfer <sanad_id> <to_address>` — Transfer Sanad
- `csv sanad consume <sanad_id>` — Consume Sanad

### Proof Operations

- `csv proof generate --chain <chain> <sanad_id> -o <file>` — Generate inclusion proof
- `csv proof verify --chain <chain> --proof-file <file>` — Verify proof on destination chain
- `csv proof verify-cross-chain --source <chain> --dest <chain> <file>` — Cross-chain proof verification

### Cross-Chain Transfers

- `csv cross-chain transfer --from <chain> --to <chain> --sanad-id <id> --dest-owner <addr>` — Initiate transfer
- `csv cross-chain status <transfer_id>` — Check transfer status
- `csv cross-chain list [--from <chain>] [--to <chain>]` — List transfers
- `csv cross-chain retry <transfer_id>` — Retry failed transfer

### Seal Operations

- `csv seal create --chain <chain> --value <amount>` — Create a seal
- `csv seal consume --chain <chain> <seal_ref>` — Consume a seal
- `csv seal verify --chain <chain> <seal_ref>` — Verify seal status
- `csv seal list [--chain <chain>]` — List seals

### Content Management

- `csv content create --input <file> --output <file>` — Create Merkle content tree
- `csv content prove --tree <file> --index <n>` — Generate Merkle proof for leaf
- `csv content verify --tree <file> [--leaf <data>] [--leaf-index <n>]` — Verify tree and leaf inclusion
- `csv content encrypt --tree <file> --key-id <id> [--algorithm <algo>]` — Encrypt subtree
- `csv content disclose --tree <file> --include <indices>` — Create selective disclosure proof
- `csv content attach add --tree <file> --file <path> -m <type>` — Add attachment reference
- `csv content participants add --tree <file> --key <hex> -r <role>` — Add participant
- `csv content claims create --tree <file> -p <predicate> -d <description>` — Create content claim

### Trust Management

- `csv trust status` — Check trust package status
- `csv trust export -o <file>` — Export trust package
- `csv trust import <file>` — Import trust package
- `csv trust verify <file>` — Verify trust package
- `csv trust rotate <height> <hash>` — Rotate to new checkpoint

### Runtime Monitoring

- `csv runtime status` — Health status and operational mode
- `csv runtime health` — Per-component health checks
- `csv runtime admission` — Admission control pressure
- `csv runtime events --count <n>` — Recent runtime events

### Validation & Inspection

- `csv validate consignment <file>` — Validate consignment
- `csv validate proof <proof> --chain <chain>` — Validate proof
- `csv validate seal <seal_ref>` — Check seal consumption
- `csv validate offline --file <proof>` — Offline proof verification
- `csv inspect replay --id <hex>` — Inspect replay registry
- `csv inspect merkle --root <hex>` — Inspect Merkle root

### Schema Tooling

- `csv schema validate --file <schema.json>` — Validate schema
- `csv schema compile --file <schema.json> --out <output>` — Compile schema
- `csv schema diff --left <v1.json> --right <v2.json>` — Diff schemas

### End-to-End Testing

- `csv test run --chain-pair <source:dest>` — Run specific chain pair test
- `csv test run-all` — Run all 9 chain pair tests
- `csv test scenario <name>` — Run specific scenario
- `csv test results` — View test results

## Global Flags

All commands support these global flags:

| Flag | Short | Description |
|------|-------|-------------|
| `--verbose` | `-v` | Enable debug logging |
| `--canonical` | | Emit canonical CBOR (hex) instead of pretty JSON |
| `--proof-tree` | | Emit proof DAG/Merkle tree structure |
| `--config` | `-C` | Config file path (default: `~/.csv/config.toml`) |

## Design Principles

- **Stateless**: CLI holds no protocol authority state
- **Delegation**: All protocol operations delegated to csv-runtime
- **No direct chain access**: CLI must not import chain adapters directly
- **Crash-safe**: Runtime provides crash-safe recovery via execution journal
- **Testnet-first**: All commands work with testnet configurations by default

## Dependencies

- `csv-runtime`: Runtime orchestration (holds all protocol authority)
- `csv-sdk`: SDK facade for operations
- `csv-admission`: Admission control types
- `csv-observability`: Runtime health types
- `csv-content`: Content tree and selective disclosure
- `csv-keys`: Key management
- `clap`: CLI argument parsing

## Configuration

The CLI uses `~/.csv/config.toml` for chain configuration:

```toml
data_dir = "~/.csv/data"

[chains.bitcoin]
rpc_url = "https://mempool.space/signet/api/"
network = "test"
finality_depth = 6

[chains.ethereum]
rpc_url = "https://ethereum-sepolia-rpc.publicnode.com"
network = "test"
chain_id = 11155111
finality_depth = 15
```

State is stored encrypted at `~/.csv/unified_storage.json` using AES-256-GCM with Argon2id key derivation.

## Examples

See `csv-examples/cli-tutorial/` for shell script examples:

- `quick-start.sh` — Quick start workflow
- `content-management.sh` — Content tree operations
- `trust-management.sh` — Trust package operations
- `cross-chain-transfer.sh` — Cross-chain transfer workflow

## Full Tutorial

See `csv-cli-tutorial.md` for a comprehensive tutorial with testnet examples covering all CLI commands.

## License

MIT OR Apache-2.0
