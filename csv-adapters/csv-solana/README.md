# csv-solana

Solana chain adapter for CSV Protocol.

## Overview

`csv-solana` provides the Solana-specific implementation of the CSV Protocol chain adapter interface, enabling seal operations, proof generation, and minting on the Solana blockchain.

## Key Features

- **Seal protocol**: Solana-specific seal operations
- **Proof generation**: Merkle proof generation for Solana
- **Minting**: Sanad minting on Solana
- **RPC client**: Solana RPC interaction
- **Account management**: Solana account operations
- **Transaction building**: Solana transaction construction

## Architecture Role

`csv-solana` is the Solana chain adapter that:

- Implements the `ChainBackend` trait for Solana
- Provides Solana-specific seal operations
- Generates Solana-specific proofs
- Handles Solana transaction submission and finality

## Dependencies

- `solana-sdk`: Solana SDK
- `solana-client`: Solana RPC client
- `csv-protocol`: Protocol types and traits
- `csv-proof`: Proof types
- `csv-hash`: Hash types
- `thiserror`: Error handling

## Modules

- **seal_protocol**: Seal operations
- **proofs**: Proof generation
- **mint**: Sanad minting
- **ops**: Chain operations
- **node**: Solana node interaction

## Usage Example

```rust
use csv_solana::{SolanaBackend, SolanaConfig};

let config = SolanaConfig::new("https://api.mainnet-beta.solana.com");
let backend = SolanaBackend::new(config)?;

let seal = backend.lock_seal(/* ... */).await?;
let proof = backend.generate_proof(&seal).await?;
```

## Solana-Specific Features

- **Account-based seals**: Uses Solana account model
- **Program-based operations**: Interacts with CSV Solana program
- **Recent blockhash**: Uses Solana's recent blockhash for transactions
- **Rent exemption**: Handles Solana rent exemption

## Design Principles

- **Solana-native**: Follows Solana conventions
- **Protocol-compliant**: Implements CSV protocol correctly
- **Efficient**: Minimizes RPC calls
- **Error-handling**: Comprehensive error types

## License

MIT OR Apache-2.0
