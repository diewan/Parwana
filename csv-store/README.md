# csv-store

Persistence layer for the CSV Protocol — seal storage, anchor storage, and replay registry.

## Features

- **sqlite** — SQLite backend (enabled by default)
- **file-storage** — Filesystem-based storage
- **browser-storage** — IndexedDB browser storage (WASM)
- **encrypted-storage** — AES-GCM encrypted storage

## Security Notes

- New browser encrypted storage keys use PBKDF2-SHA256 with 600,000 iterations.
- Existing encrypted browser material written with older iteration counts should be migrated by decrypting with the old parameters and re-saving with the current manager.

## License

MIT OR Apache-2.0
