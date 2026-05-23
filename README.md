# CSV Protocol

Chain-agnostic client-side validation protocol for cross-chain seal verification.

## Workspace Crates

| Crate | Description |
|-------|-------------|
| [csv-core](csv-core/) | Core protocol types, traits, and proof system |
| [csv-runtime](csv-runtime/) | Runtime orchestration, lease management, replay detection |
| [csv-sdk](csv-sdk/) | Unified SDK — single entry point for all operations |
| [csv-cli](csv-cli/) | CLI tool for seals, proofs, sanads, and wallets |
| [csv-wallet](csv-wallet/) | Multi-chain wallet with Dioxus UI |
| [csv-keys](csv-keys/) | Secure key storage with BIP-39/BIP-44 support |
| [csv-store](csv-store/) | Persistence layer (SQLite, browser storage) |
| [csv-p2p](csv-p2p/) | P2P proof transport via Nostr |
| [csv-observability](csv-observability/) | Metrics and logging utilities |

## Chain Adapters

| Adapter | Chain |
|---------|-------|
| [csv-bitcoin](csv-adapters/csv-bitcoin/) | Bitcoin UTXO seals |
| [csv-ethereum](csv-adapters/csv-ethereum/) | Ethereum seal protocols |
| [csv-solana](csv-adapters/csv-solana/) | Solana seal protocols |
| [csv-sui](csv-adapters/csv-sui/) | Sui seal protocols |
| [csv-aptos](csv-adapters/csv-aptos/) | Aptos seal protocols |
| [csv-celestia](csv-adapters/csv-celestia/) | Celestia data availability |

## Smart Contracts

- [Ethereum](csv-contracts/ethereum/) — Foundry
- [Solana](csv-contracts/solana/) — Anchor
- [Sui](csv-contracts/sui/) — Sui Move
- [Aptos](csv-contracts/aptos/) — Aptos Move

## Quick Start

```bash
# Build everything
CXXFLAGS="-include cstdint" cargo build --workspace --all-features

# Run tests
CXXFLAGS="-include cstdint" cargo test --workspace --all-features

# Local development mode (switch git deps to path deps)
./scripts/dev.sh

# Publish mode (switch path deps back to git deps)
./scripts/publish.sh
```

## Architecture

```
csv-sdk (public facade)
  └── csv-runtime (orchestration)
        └── csv-core (protocol types & traits)
              ├── csv-bitcoin
              ├── csv-ethereum
              ├── csv-solana
              ├── csv-sui
              ├── csv-aptos
              └── csv-celestia
```

## License

MIT OR Apache-2.0
