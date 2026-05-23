# AGENTS.md — CSV Protocol Operational Guide

## Repo structure

Rust monorepo (Cargo workspace, edition 2024, rust-version 1.93). Root crate is `csv-protocol`.

**Workspace members (20 crates):**

**Phase 1 restructuring crates (new architecture):**

- `csv-protocol` — protocol orchestration layer
- `csv-codec` — canonical serialization (CBOR)
- `csv-hash` — hash types, SanadId, replay ID types
- `csv-proof` — proof bundle types, replay ID derivation
- `csv-verifier` — canonical proof verification
- `csv-schema` — schema definitions
- `csv-content` — content types
- `csv-storage` — storage traits and backends (RocksDB, PostgreSQL, in-memory)
- `csv-testkit` — test fixtures and adversarial testing
- `csv-contract-bindings` — smart contract bindings

**Legacy crates (being refactored/deprecated):**

- `csv-core` — legacy protocol types (migration in progress)
- `csv-runtime` — `TransferCoordinator`, lease management, replay DB, circuit breakers, execution journal (depends only on csv-core/csv-protocol)
- `csv-sdk` — public SDK facade
- `csv-cli` — CLI binary (must not import chain adapters directly)
- `csv-keys` — key management
- `csv-store` — legacy state storage
- `csv-p2p` — peer-to-peer networking
- `csv-observability` — metrics and observability

**Chain adapters** (under `csv-adapters/`, each implements `SealProtocol` + `ChainBackend` traits):
`csv-adapters/csv-bitcoin`, `csv-adapters/csv-ethereum`, `csv-adapters/csv-solana`, `csv-adapters/csv-sui`, `csv-adapters/csv-aptos`, `csv-adapters/csv-celestia`

**Other crates:** `csv-mcp-server/`, `csv-examples/` (not in workspace)

**Smart contracts:** `csv-contracts/ethereum/` (Foundry), `csv-contracts/solana/` (Anchor), `csv-contracts/sui/` (Sui Move), `csv-contracts/aptos/` (Aptos Move).

**Chain configs:** `chains/*.toml` — per-chain TOML configs (Solana, Ethereum, Sui, Bitcoin, Aptos).

**Documentation:** `csv-docs/` — all protocol documentation (no `docs/` directory at root).

**Note:** `csv-wallet`, `csv-explorer/*`, and `typescript-sdk/` do not exist in the current codebase. References to them in old documentation should be removed.

## Commands

```bash
# Build everything
CXXFLAGS="-include cstdint" cargo build --workspace --all-features

# Run all tests
CXXFLAGS="-include cstdint" cargo test --workspace --all-features

# Run doc tests
cargo test --workspace --doc

# Lint + format check
cargo fmt --all -- --check
cargo clippy --workspace --all-features -- -D warnings

# WASM32 build check (csv-runtime only)
cargo build --package csv-runtime --no-default-features --target wasm32-unknown-unknown

# Fuzz targets (cd fuzz first)
cargo install cargo-fuzz
cd fuzz && cargo fuzz run proof_bundle_decode -- -max_total_time=60

# Golden corpus tests
cargo test -p csv-core --test golden

# Security audit
cargo install cargo-audit && cargo audit

# Explorer (Rust + Next.js) — NOT AVAILABLE (csv-explorer removed)
# cd csv-explorer && cargo build --workspace

# Contracts
cd csv-contracts/ethereum/contracts && forge build
cd csv-contracts/solana/contracts && NO_DNA=1 anchor build
cd csv-contracts/sui/contracts && sui move build
cd csv-contracts/aptos/contracts && aptos move compile
```

## Architecture rules (enforced by CI)

- `csv-core` must NOT import any chain adapter (`csv-adapters/csv-bitcoin`, etc.)
- `csv-cli` must NOT import chain adapters directly — use `csv-runtime`
- `csv-runtime` depends only on `csv-core`/`csv-protocol` — no chain adapter imports
- `serde_json` is forbidden in canonical hashing paths; use `canonical_cbor`
- `persistent` feature is incompatible with wasm32 (compile_error fires)
- `experimental` feature gates: `vm`, `rgb`, `commit_mux`
- Finality is NEVER optional — all runtime modes enforce strict finality
- CLI holds NO protocol authority state (leases, transfers) — all delegated to csv-runtime
- Execution journal (`execution_journal.rs`) provides crash-safe phase tracking

## Testing notes

- `csv-core` golden fixtures live in `csv-core/tests/golden/*.cbor` — regenerate with `cargo run -p csv-core --bin generate_golden_fixtures`
- Integration tests are `#[ignored]` and require RPC secrets (signet, sepolia, sui testnet)
- nextest config: 30s slow-timeout for crypto tests (`.config/nextest.toml`)
- Execution journal tests validate crash recovery paths

## Contracts

- Ethereum: Foundry (`forge build` in `csv-contracts/ethereum/contracts`)
- Solana: Anchor (`NO_DNA=1 anchor build` in `csv-contracts/solana/contracts`)
- Sui: Sui Move (`sui move build` in `csv-contracts/sui/contracts`)
- Aptos: Aptos CLI (`aptos move compile` in `csv-contracts/aptos/contracts`)

## Security

See `.agents/AGENT.md` for protocol invariants, forbidden patterns, and verification rules.
See `csv-docs/THREAT_MODEL.md` for the threat model.
See `csv-docs/PROTOCOL_INVARIANTS.md` and `csv-docs/PROTOCOL_CONSTITUTION.md` for protocol rules.
