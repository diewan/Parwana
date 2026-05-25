# csv-store

Persistence layer for the CSV Protocol — seal storage, anchor storage, and replay registry.

## Overview

`csv-store` provides persistence backends for CSV protocol data, supporting multiple storage engines for different deployment scenarios.

## Features

- **sqlite** — SQLite backend (enabled by default)
- **file-storage** — Filesystem-based storage
- **browser-storage** — IndexedDB browser storage (WASM)
- **encrypted-storage** — AES-GCM encrypted storage

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

## Dependencies

- `sqlx`: SQLite database access
- `thiserror`: Error handling
- `aes-gcm`: AES-GCM encryption

## License

MIT OR Apache-2.0
