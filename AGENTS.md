# AGENTS.md — CSV Protocol Operational Guide

## Repo structure

Rust monorepo (Cargo workspace, edition 2024, rust-version 1.95). Root crate is `csv-adapter`.

**Core crates:**
- `csv-core` — protocol types, traits, proof bundles, replay registry, canonical serialization
- `csv-runtime` — `TransferCoordinator`, lease management, replay DB, circuit breakers (depends only on csv-core)
- `csv-sdk` — public SDK facade
- `csv-cli` — CLI binary (must not import chain adapters directly)
- `csv-wallet` — wallet (must not import chain adapters directly)

**Chain adapters** (each implements `SealProtocol` + `ChainBackend` traits):
`csv-bitcoin`, `csv-ethereum`, `csv-solana`, `csv-sui`, `csv-aptos`, `csv-celestia`, `csv-stark`

**Other crates:** `csv-keys`, `csv-store`, `csv-p2p`, `csv-observability`, `csv-explorer/*`, `xtask`, `fuzz`

**TypeScript SDK:** `typescript-sdk/` (NPM package). WASM bindings in `typescript-sdk/wasm/`.

**Smart contracts:** `csv-contracts/ethereum/` (Foundry), `csv-contracts/solana/` (Anchor), `csv-contracts/sui/` (Sui Move), `csv-contracts/aptos/` (Aptos Move).

**Chain configs:** `chains/*.toml` — per-chain TOML configs (Solana, Ethereum, Sui, Bitcoin, Aptos).

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

# WASM32 build check
cargo build --package csv-runtime --no-default-features --target wasm32-unknown-unknown
cargo build --package csv-wallet --no-default-features --features "csv-bitcoin,csv-ethereum" --target wasm32-unknown-unknown

# Fuzz targets (cd fuzz first)
cargo install cargo-fuzz
cd fuzz && cargo fuzz run proof_bundle_decode -- -max_total_time=60

# Golden corpus tests
cargo test -p csv-core --test golden

# RLP regression test
cargo test --package csv-wallet test_eth_rlp -- --nocapture
# Requires: ETH_CHAIN_ID=11155111

# Security audit
cargo install cargo-audit && cargo audit

# Explorer (Rust + Next.js)
cd csv-explorer && cargo build --workspace
# UI: see csv-explorer/build-ui.sh
```

## Architecture rules (enforced by CI)

- `csv-core` must NOT import any chain adapter (`csv-bitcoin`, `csv-ethereum`, etc.)
- `csv-cli` and `csv-wallet` must NOT import chain adapters directly — use `csv-runtime`
- `csv-runtime` depends only on `csv-core` — no chain adapter imports
- `serde_json` is forbidden in canonical hashing paths; use `canonical_cbor`
- `persistent` feature is incompatible with wasm32 (compile_error fires)
- `experimental` feature gates: `vm`, `rgb`, `commit_mux`

## Testing notes

- `csv-core` golden fixtures live in `csv-core/tests/golden/*.cbor` — regenerate with `cargo run -p csv-core --bin generate_golden_fixtures`
- Integration tests are `#[ignored]` and require RPC secrets (signet, sepolia, sui testnet)
- `csv-wallet` RLP test requires `ETH_CHAIN_ID` env var
- nextest config: 30s slow-timeout for crypto tests (`.config/nextest.toml`)

## Contracts

- Ethereum: Foundry (`forge build` in `csv-contracts/ethereum/contracts`)
- Solana: Anchor (`NO_DNA=1 anchor build` in `csv-contracts/solana/contracts`)
- Sui: Sui Move (`sui move build` in `csv-contracts/sui/contracts`)
- Aptos: Aptos CLI (`aptos move compile` in `csv-contracts/aptos/contracts`)

## Security

See `.agents/AGENT.md` for protocol invariants, forbidden patterns, and verification rules.
See `docs/THREAT_MODEL.md` for the threat model.
See `docs/PROTOCOL_INVARIANTS.md` and `docs/PROTOCOL_CONSTITUTION.md` for protocol rules.
