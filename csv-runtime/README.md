# csv-runtime

Runtime orchestration engine for the CSV protocol. Manages transfer coordination, lease management, replay detection, and circuit breakers.

## Features

- **persistent** — Persistent storage with RocksDB (enabled by default)
- **postgres** — PostgreSQL-backed replay database
- **serde** — Serialization support

## Architecture

`csv-runtime` depends only on `csv-core` and provides the high-level orchestration layer. It does not import chain adapters directly.

## License

MIT OR Apache-2.0
