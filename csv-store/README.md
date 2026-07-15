# csv-store

Persistence layer for the Parwana — seal storage, anchor storage, and replay registry.

## Overview

`csv-store` provides persistence backends for Parwana data, supporting multiple storage engines for different deployment scenarios.

## Features

- **sqlite** — SQLite backend using rusqlite (enabled by default)
- **file-storage** — Filesystem-based storage via the unified state module
- **browser-storage** — IndexedDB browser storage (WASM)
- **encrypted-storage** — AES-GCM encrypted storage

## Storage Architecture

`csv-store` uses a unified state module (`src/state/`) that provides:

- **Domain types**: Sanads, transfers, contracts, seals, proofs, transactions (see `state/domain.rs`)
- **Storage backends**: Pluggable storage implementations (see `state/backend.rs`)
- **State management**: Unified storage interface for all Parwana state (see `state/storage.rs`)

The legacy `SqliteSealStore` implementation has been retired in favor of the unified state module architecture. The state module provides a cleaner abstraction that supports multiple backends (SQLite, filesystem, browser IndexedDB) through a common interface.

## Storage Types

- **Seal storage**: Persist seal references and metadata
- **Anchor storage**: Store commitment anchors
- **Replay registry**: Track nullifiers for replay protection
- **Transfer registry**: Record cross-chain transfers

## Security Notes

- New browser encrypted storage keys use PBKDF2-SHA256 with 600,000 iterations
- Existing encrypted browser material written with older iteration counts should be migrated by decrypting with the old parameters and re-saving with the current manager

## Architecture Role

`csv-store` provides:

- Cross-platform persistence (native, browser)
- Multiple storage backends (SQLite, filesystem, IndexedDB)
- Encrypted storage support
- Migration support for key parameters
- Unified state module for protocol data management

## Dependencies

- `rusqlite`: SQLite database access (bundled, enabled via `sqlite` feature)
- `thiserror`: Error handling
- `aes-gcm`: AES-GCM encryption (for encrypted-storage feature)
- `csv-protocol`: Protocol types and traits
- `csv-hash`: Hash types and replay ID types
- `csv-proof`: Proof bundle types

## License

MIT OR Apache-2.0
