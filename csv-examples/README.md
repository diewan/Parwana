# CSV Protocol Examples

This directory contains example code and tutorials demonstrating how to use the CSV Protocol SDK and CLI.

## Overview

The examples are organized into three categories:

- **Getting Started** - Basic examples for newcomers to the CSV Protocol
- **Advanced** - Complex use cases and integration patterns
- **CLI Tutorial** - Shell scripts and documentation for the CSV CLI tool

## Prerequisites

- Rust 1.93+ (for Rust examples)
- Built CSV CLI binary (for CLI tutorial)
- Access to testnet RPC endpoints (configured by default)

## Building Examples

All Rust examples are defined in `Cargo.toml` and can be run using cargo:

```bash
# Build all examples
cargo build --package csv-examples --all-features

# Run a specific example
cargo run --example subscriptions --features "all-chains,tokio"
```

## Getting Started Examples

### subscriptions.rs

Demonstrates how to create and manage subscription sanads that can be transferred across chains.

**Run:**

```bash
cargo run --example subscriptions --features "all-chains,tokio"
```

**What it demonstrates:**

- Initializing the CSV SDK client with all chains

- Creating a sanad on Bitcoin

- Querying sanad status

- Initiating cross-chain transfer to Ethereum

- Checking transfer status

## Advanced Examples

### gaming.rs

Shows how gaming assets can be represented as sanads and transferred between chains for different game ecosystems.

**Run:**

```bash
cargo run --example gaming --features "all-chains,tokio"
```

**What it demonstrates:**

- Creating gaming assets (weapons, shields) as sanads

- Transferring assets between game ecosystems (Bitcoin → Ethereum)

- Listing player asset inventory

- Integration points for game clients

### parallel_verification.rs

Demonstrates parallel proof verification for improved performance when handling multiple proofs.

**Run:**

```bash
cargo run --example parallel_verification --features "all-chains,tokio"
```

**What it demonstrates:**

- Concurrent proof verification using tokio

- Performance optimization patterns

- Batch processing of proof bundles

### performance.rs

Performance benchmarking example for measuring CSV Protocol operations.

**Run:**

```bash
cargo run --example performance --features "all-chains,tokio"
```

**What it demonstrates:**

- Benchmarking sanad creation

- Measuring proof generation times

- Cross-chain transfer performance metrics

- Memory and CPU usage profiling

## CLI Tutorial

The `cli-tutorial/` directory contains comprehensive documentation and shell scripts for using the CSV CLI tool.

### Documentation

- **csv-cli-tutorial.md** - Complete CLI reference with examples for all commands (moved to repository root as `csv-cli-tutorial.md`)

### Shell Scripts

- **quick-start.sh** - Quick setup guide for first-time users

- **cross-chain-transfer.sh** - End-to-end cross-chain transfer workflow

- **content-management.sh** - Content tree creation and management

- **trust-management.sh** - Trust package operations

**Run scripts:**

```bash
cd cli-tutorial
bash quick-start.sh
bash cross-chain-transfer.sh
```

## CLI Quick Reference

For comprehensive CLI documentation, see the main tutorial at the repository root:

```bash
# View the full CLI tutorial
cat ../csv-cli-tutorial.md
```

### Common CLI Commands

```bash
# Build the CLI
cargo build -p csv-cli --release

# Chain management
csv chain list
csv chain status --chain ethereum

# Wallet operations
csv wallet init --network test --words 12
csv wallet balance --chain ethereum

# Sanad operations
csv sanad create --chain bitcoin --value 100000
csv sanad list

# Proof operations
csv proof generate --chain ethereum <sanad_id> -o proof.json
csv proof verify --chain sui --proof-file proof.json

# Cross-chain transfers
csv cross-chain materialize --from bitcoin --to sui --sanad-id <id> --dest-owner <addr>
```

## Architecture Notes

All Rust examples use the `csv-sdk` crate, which provides a high-level facade over the CSV Protocol runtime:

- **csv-sdk** - Public SDK facade
- **csv-runtime** - Orchestration, execution journal, health monitoring
- **csv-protocol** - Protocol types and traits
- **csv-coordinator** - Per-chain execution cells
- **csv-adapters** - Chain-specific implementations (Bitcoin, Ethereum, Solana, Sui, Aptos, Celestia)

## Testing on Testnet

Most examples are configured to use testnet endpoints by default. To run examples with real transactions:

1. Ensure you have testnet funds on the relevant chains
2. Initialize your wallet: `csv wallet init --network test --words 12`
3. Run examples with the `all-chains` feature flag

## Additional Resources

- **Repository Documentation** - See `csv-docs/` for protocol specifications
- **CLI Tutorial** - See `csv-cli-tutorial.md` at repository root for comprehensive CLI guide
- **Architecture Guide** - See `AGENTS.md` for architecture rules and crate structure
- **Security** - See `csv-docs/THREAT_MODEL.md` for security considerations

## Contributing Examples

To add a new example:

1. Create the Rust file in the appropriate directory (`getting-started/` or `advanced/`)
2. Add an `[[example]]` entry to `Cargo.toml`
3. Include documentation comments explaining what the example demonstrates
4. Ensure the example builds with `cargo build --package csv-examples --all-features`

## License

These examples are part of the CSV Protocol project and follow the same license terms.
