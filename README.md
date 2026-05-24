# CSV Protocol

Chain-agnostic client-side validation protocol for cross-chain seal verification.

## Workspace Crates (20 members)

**Phase 1 restructuring crates (new architecture):**

| Crate | Description |
|-------|-------------|
| [csv-protocol](csv-protocol/) | Protocol orchestration layer |
| [csv-codec](csv-codec/) | Canonical serialization (CBOR) |
| [csv-hash](csv-hash/) | Hash types, SanadId, replay ID types |
| [csv-proof](csv-proof/) | Proof bundle types, replay ID derivation |
| [csv-verifier](csv-verifier/) | Canonical proof verification |
| [csv-schema](csv-schema/) | Schema definitions |
| [csv-content](csv-content/) | Content types |
| [csv-storage](csv-storage/) | Storage traits and backends (RocksDB, PostgreSQL, in-memory) |
| [csv-testkit](csv-testkit/) | Test fixtures and adversarial testing |
| [csv-contract-bindings](csv-contract-bindings/) | Smart contract bindings |

**Legacy crates (being refactored/deprecated):**

| Crate | Description |
|-------|-------------|
| [csv-core](csv-core/) | Core protocol types, traits, and proof system (migration in progress) |
| [csv-runtime](csv-runtime/) | Runtime orchestration, lease management, replay detection, execution journal |
| [csv-sdk](csv-sdk/) | Unified SDK — single entry point for all operations |
| [csv-cli](csv-cli/) | CLI tool (stateless — delegates to csv-runtime) |
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
  └── csv-runtime (orchestration + execution journal)
        └── csv-protocol / csv-core (protocol types & traits)
              ├── csv-adapters/csv-bitcoin
              ├── csv-adapters/csv-ethereum
              ├── csv-adapters/csv-solana
              ├── csv-adapters/csv-sui
              ├── csv-adapters/csv-aptos
              └── csv-adapters/csv-celestia
```

## Notes

- `csv-wallet`, `csv-explorer/*`, and `typescript-sdk/` do not exist in the current codebase.
- All documentation is in `csv-docs/` (not `docs/`).
- Finality is NEVER optional — all runtime modes enforce strict finality.
- CLI holds NO protocol authority state (leases, transfers) — all delegated to csv-runtime.
- Proof bundles carry their signature scheme, and `csv-runtime` rejects bundles whose scheme does not match the source chain adapter.
- Runtime transfer recovery persists `transition_id`, lock/mint transaction hashes, and non-empty canonical CBOR checkpoints.
- Nullifier/replay retention is 7 days by default; replay records are state-transitioned (`Pending`, `Consumed`, `RolledBack`) rather than silently deleted.
- Browser keystore/storage PBKDF2-SHA256 derivation uses 600,000 iterations for newly written encrypted material.

## License

MIT OR Apache-2.0
