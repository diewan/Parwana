# csv-storage

Storage traits and backends (RocksDB, PostgreSQL, in-memory) for Parwana.

## Overview

`csv-storage` provides storage abstraction and implementations for the Parwana, including replay databases, transfer registries, and event stores.

## Key Features

- **Storage traits**: Generic storage interface
- **Multiple backends**: RocksDB, PostgreSQL, in-memory
- **Replay database**: Nullifier tracking and replay protection
- **Transfer registry**: Cross-chain transfer tracking
- **Event store**: Event persistence and retrieval
- **Conformance tests**: Backend conformance testing

## Modules

- **traits**: Generic storage interface definitions
- **backends/in_memory**: In-memory storage backend
- **backends/rocksdb**: RocksDB storage backend
- **backends/postgres**: PostgreSQL storage backend
- **errors**: Storage error types

## Architecture Role

`csv-storage` is the persistence layer that:

- Provides a unified storage interface
- Supports multiple backend implementations
- Ensures conformance across backends
- Enables backend swapping without code changes

## Dependencies

- `csv-protocol`: Protocol types (HashEntry for transfer registry)
- `csv-hash`: Hash types
- `csv-proof`: Proof types (ReplayId)
- `rocksdb`: RocksDB backend (optional)
- `sqlx`: PostgreSQL backend (optional)
- `async-trait`: Async trait definitions
- `thiserror`: Error handling

## Storage Traits

- **ReplayDatabase**: Nullifier tracking and replay protection
- **EventStore**: Event persistence and retrieval
- **TransferRegistry**: Cross-chain transfer tracking

## Backend Features

- **in-memory**: Fast, ephemeral storage (testing)
- **rocksdb**: Persistent, high-performance storage
- **postgres**: Persistent, SQL-based storage

## Usage Example

```rust
use csv_storage::{ReplayDatabase, InMemoryReplayDb};

let db = InMemoryReplayDb::new();
db.mark_consumed(&replay_id).await?;
let is_consumed = db.is_consumed(&replay_id).await?;
```

## Design Principles

- **Backend-agnostic**: Application code doesn't depend on specific backend
- **Conformant**: All backends pass conformance tests
- **Async**: All operations are async
- **Error-handling**: Comprehensive error types

## Features

- **default**: In-memory backend only
- **persistent**: RocksDB backend
- **postgres**: PostgreSQL backend

## License

MIT OR Apache-2.0
