# csv-runtime

Runtime orchestration engine for the CSV protocol. Manages transfer coordination, lease management, replay detection, circuit breakers, and crash-safe execution journaling.

## Features

- **persistent** — Persistent storage with RocksDB (enabled by default)
- **postgres** — PostgreSQL-backed replay database
- **serde** — Serialization support

## Architecture

`csv-runtime` depends only on `csv-core` and `csv-protocol`. It provides the high-level orchestration layer including:

- **TransferCoordinator** — Single source of truth for cross-chain transfer execution
- **ExecutionJournal** — Phase-by-phase audit trail for crash-safe recovery
- **EventBus** — Structured events for observability
- **EventStore** — Durable event sourcing storage
- **Policy** — Runtime policies and circuit breakers (finality is NEVER optional)
- **Verifier** — All proof verification delegated to csv-verifier::CanonicalVerifier

The runtime does not import chain adapters directly. Chain adapters register themselves via the `AdapterRegistry` trait.

## License

MIT OR Apache-2.0
