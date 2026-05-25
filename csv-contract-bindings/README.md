# csv-contract-bindings

Smart contract bindings for CSV Protocol.

## Overview

`csv-contract-bindings` provides type-safe bindings and interfaces for interacting with CSV Protocol smart contracts across different blockchains.

## Key Features

- **Type-safe bindings**: Rust types for contract interactions
- **Multi-chain support**: Bindings for Ethereum, Solana, Sui, Aptos
- **Event parsing**: Contract event parsing and decoding
- **Transaction building**: Transaction construction helpers
- **ABI definitions**: Contract ABI and interface definitions

## Architecture Role

`csv-contract-bindings` provides:

- Type-safe contract interaction
- Cross-chain contract abstraction
- Event parsing and decoding
- Transaction building utilities

## Dependencies

- `ethers`: Ethereum interactions (optional)
- `solana-sdk`: Solana interactions (optional)
- `sui-sdk`: Sui interactions (optional)
- `aptos-sdk`: Aptos interactions (optional)
- `serde`: Serialization
- `thiserror`: Error handling

## Supported Chains

- **Ethereum**: ERC-20 style seals
- **Solana**: Program-based seals
- **Sui**: Move-based seals
- **Aptos**: Move-based seals

## Usage Example

```rust
use csv_contract_bindings::ethereum::SealContract;

let contract = SealContract::new(address, provider);
let seal_event = contract.get_seal_event(tx_hash).await?;
```

## Design Principles

- **Type-safe**: Compile-time guarantee of correct contract usage
- **Multi-chain**: Unified interface across different blockchains
- **Event-driven**: Event parsing and decoding
- **Transaction builders**: Simplify transaction construction

## Features

- **ethereum**: Ethereum contract bindings
- **solana**: Solana program bindings
- **sui**: Sui Move bindings
- **aptos**: Aptos Move bindings

## License

MIT OR Apache-2.0
